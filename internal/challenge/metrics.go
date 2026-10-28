package challenge

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	metricIssued    = "issued"
	metricSolved    = "solved"
	metricRejected  = "rejected"
	metricImmunity  = "immunity"
	metricFailOpen  = "fail_open"
	maxMetricKeys   = 4096
	metricBucket    = 2 * time.Second
	metricRetention = 7 * 24 * time.Hour
)

type metricKey struct {
	bucket       int64
	site, reason string
}
type metricRow struct {
	Bucket int64  `json:"bucket"`
	Site   string `json:"site"`
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}
type metrics struct {
	mu       sync.Mutex
	flushMu  sync.Mutex
	db       *sql.DB
	pending  map[metricKey]uint64
	lost     uint64
	degraded bool
}

func (service *Service) recordMetric(site, reason string) {
	if service.metrics != nil {
		service.metrics.record(service.clock(), site, reason)
	}
}

func openMetrics(path string) (*metrics, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS metrics (bucket INTEGER NOT NULL, site TEXT NOT NULL, reason TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (bucket, site, reason))`); err != nil {
		db.Close()
		return nil, err
	}
	return &metrics{db: db, pending: make(map[metricKey]uint64)}, nil
}

func (m *metrics) record(now time.Time, site, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch reason {
	case metricIssued, metricSolved, metricRejected, metricImmunity, metricFailOpen:
	default:
		m.lost++
		return
	}
	if !validIdentifier(site) {
		m.lost++
		return
	}
	k := metricKey{now.UTC().Truncate(metricBucket).Unix(), site, reason}
	if _, ok := m.pending[k]; !ok && len(m.pending) >= maxMetricKeys {
		m.lost++
		return
	}
	m.pending[k]++
}

func (m *metrics) dropped() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.lost }

// flush swaps out the bounded batch before touching SQLite, so request handlers
// never wait for disk I/O. A failed batch is dropped rather than queued forever.
func (m *metrics) flush(now time.Time) error {
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	m.mu.Lock()
	batch := m.pending
	m.pending = make(map[metricKey]uint64)
	m.mu.Unlock()
	err := m.writeBatch(now, batch)
	m.mu.Lock()
	m.degraded = err != nil
	if err != nil {
		for _, count := range batch {
			m.lost += count
		}
	}
	m.mu.Unlock()
	return err
}

func (m *metrics) writeBatch(now time.Time, batch map[metricKey]uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM metrics WHERE bucket < ?`, now.Add(-metricRetention).Truncate(metricBucket).Unix()); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO metrics(bucket,site,reason,count) VALUES(?,?,?,?) ON CONFLICT(bucket,site,reason) DO UPDATE SET count=count+excluded.count`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for key, count := range batch {
		if key.bucket < now.Add(-metricRetention).Truncate(metricBucket).Unix() {
			continue
		}
		if _, err = stmt.ExecContext(ctx, key.bucket, key.site, key.reason, count); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *metrics) query(from, to time.Time, limit int) ([]metricRow, error) {
	if !to.After(from) || to.Sub(from) > metricRetention || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("invalid metrics range or limit")
	}
	rows, err := m.db.Query(`SELECT bucket, site, reason, count FROM metrics WHERE bucket >= ? AND bucket < ? ORDER BY bucket, site, reason LIMIT ?`, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []metricRow{}
	for rows.Next() {
		var row metricRow
		if err := rows.Scan(&row.Bucket, &row.Site, &row.Reason, &row.Count); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (m *metrics) close() error { return m.db.Close() }
