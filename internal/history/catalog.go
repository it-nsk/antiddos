package history

// The catalog is a separate SQLite registry for isolated history results. It
// intentionally stores coverage ownership only; traffic and detections remain
// in their result databases until a later, separately designed read model.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/storage"
	_ "github.com/mattn/go-sqlite3"
)

type CatalogEntry struct {
	ImportID, ResultPath, SHA256, SourceID, AnalysisConfigID string
	From, To, CreatedAt                                      time.Time
}
type CatalogResult struct {
	Entry            CatalogEntry
	AlreadyPublished bool
}
type PublishResult struct {
	Entry            CatalogEntry
	AlreadyPublished bool
	Detections       int64
	TrafficSamples   int64
}
type CatalogTraffic struct {
	Samples []metrics.Sample
	Entries int
}
type CatalogDetection struct {
	ImportID string
	storage.HistoricalDetection
}
type CatalogInterval struct {
	From time.Time
	To   time.Time
}
type CatalogCoverage struct {
	SourceID string
	From     time.Time
	To       time.Time
	Covered  []CatalogInterval
	Gaps     []CatalogInterval
}

// CatalogEntries reads ownership metadata only. It neither opens result
// databases nor creates/migrates the catalog, so it is safe for audit tools.
func CatalogEntries(ctx context.Context, catalogPath string) ([]CatalogEntry, error) {
	if !filepath.IsAbs(catalogPath) {
		return nil, fmt.Errorf("catalog path must be absolute")
	}
	if err := validateCatalogPath(catalogPath, false); err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: filepath.Clean(catalogPath)}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("_busy_timeout", "5000")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT import_id,result_path,result_sha256,source_id,analysis_config_id,period_from_unix_ns,period_to_unix_ns,created_at_unix_ms FROM history_catalog_entries ORDER BY source_id,period_from_unix_ns,import_id`)
	if err != nil {
		return nil, fmt.Errorf("read history catalog: %w", err)
	}
	defer rows.Close()
	entries := []CatalogEntry{}
	for rows.Next() {
		var entry CatalogEntry
		var from, to, created int64
		if err := rows.Scan(&entry.ImportID, &entry.ResultPath, &entry.SHA256, &entry.SourceID, &entry.AnalysisConfigID, &from, &to, &created); err != nil {
			return nil, err
		}
		entry.From = time.Unix(0, from)
		entry.To = time.Unix(0, to)
		entry.CreatedAt = time.UnixMilli(created)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// CatalogCoverage reports catalog ownership for exactly one source in a
// requested half-open range. The intervals are registry metadata, not a claim
// about live traffic or about unregistered historical files.
func ReadCatalogCoverage(ctx context.Context, catalogPath, sourceID string, from, to time.Time) (CatalogCoverage, error) {
	if sourceID == "" || !from.Before(to) {
		return CatalogCoverage{}, fmt.Errorf("source and ordered coverage range are required")
	}
	entries, err := CatalogEntries(ctx, catalogPath)
	if err != nil {
		return CatalogCoverage{}, err
	}
	coverage := CatalogCoverage{SourceID: sourceID, From: from, To: to, Covered: []CatalogInterval{}, Gaps: []CatalogInterval{}}
	cursor := from
	for _, entry := range entries {
		if entry.SourceID != sourceID || !entry.From.Before(to) || !from.Before(entry.To) {
			continue
		}
		start, end := maxTime(from, entry.From), minTime(to, entry.To)
		if cursor.Before(start) {
			coverage.Gaps = append(coverage.Gaps, CatalogInterval{From: cursor, To: start})
		}
		coverage.Covered = append(coverage.Covered, CatalogInterval{From: start, To: end})
		if cursor.Before(end) {
			cursor = end
		}
	}
	if cursor.Before(to) {
		coverage.Gaps = append(coverage.Gaps, CatalogInterval{From: cursor, To: to})
	}
	return coverage, nil
}

// PublishToDatabase appends a verified isolated result to a target dashboard
// database. It is explicit, idempotent, and rejects any target overlap.
func PublishToDatabase(ctx context.Context, resultPath, targetPath, confirmImport string) (PublishResult, error) {
	if !filepath.IsAbs(targetPath) {
		return PublishResult{}, fmt.Errorf("target database path must be absolute")
	}
	if filepath.Clean(resultPath) == filepath.Clean(targetPath) {
		return PublishResult{}, fmt.Errorf("target database must not be the isolated result")
	}
	entry, err := catalogCandidate(ctx, resultPath)
	if err != nil {
		return PublishResult{}, err
	}
	if confirmImport == "" || entry.ImportID != confirmImport {
		return PublishResult{}, fmt.Errorf("isolated result import ID is %s; it does not match explicit confirmation", entry.ImportID)
	}
	store, err := storage.OpenHistoricalPublisher(targetPath)
	if err != nil {
		return PublishResult{}, err
	}
	defer store.Close()
	published, err := store.PublishHistoricalResult(ctx, resultPath, entry.ImportID, entry.SourceID, entry.From, entry.To)
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{Entry: entry, AlreadyPublished: published.AlreadyPublished, Detections: published.Detections, TrafficSamples: published.TrafficSamples}, nil
}

// CatalogTraffic aggregates only registered, non-overlapping isolated result
// samples. It never reads a configured live database. Each catalog entry is
// hash-verified before use, so a changed result is rejected rather than mixed.
func ReadCatalogTraffic(ctx context.Context, catalogPath string, from, to time.Time) (CatalogTraffic, error) {
	if !from.Before(to) || from.Unix()%int64(metrics.SampleInterval/time.Second) != 0 || to.Unix()%int64(metrics.SampleInterval/time.Second) != 0 {
		return CatalogTraffic{}, fmt.Errorf("traffic range must be ordered and aligned to 15-second buckets")
	}
	entries, err := CatalogEntries(ctx, catalogPath)
	if err != nil {
		return CatalogTraffic{}, err
	}
	byBucket := map[int64]metrics.Sample{}
	used := 0
	for _, entry := range entries {
		if !entry.From.Before(to) || !from.Before(entry.To) {
			continue
		}
		candidate, err := catalogCandidate(ctx, entry.ResultPath)
		if err != nil {
			return CatalogTraffic{}, fmt.Errorf("verify catalog import %s: %w", entry.ImportID, err)
		}
		if candidate.SHA256 != entry.SHA256 || candidate.ImportID != entry.ImportID {
			return CatalogTraffic{}, fmt.Errorf("catalog import %s no longer matches its registered result", entry.ImportID)
		}
		reader, err := storage.OpenReader(entry.ResultPath)
		if err != nil {
			return CatalogTraffic{}, err
		}
		start := maxTime(from, entry.From)
		end := minTime(to, entry.To)
		samples, readErr := reader.TrafficRange(ctx, entry.SourceID, start, end)
		closeErr := reader.Close()
		if readErr != nil {
			return CatalogTraffic{}, readErr
		}
		if closeErr != nil {
			return CatalogTraffic{}, closeErr
		}
		used++
		for _, sample := range samples {
			total := byBucket[sample.BucketStartUnix]
			total.BucketStartUnix = sample.BucketStartUnix
			total.IntervalSeconds = sample.IntervalSeconds
			total.Requests += sample.Requests
			total.MatchedRequests += sample.MatchedRequests
			total.ResponseBytes += sample.ResponseBytes
			total.KnownResponseByteRows += sample.KnownResponseByteRows
			byBucket[sample.BucketStartUnix] = total
		}
	}
	keys := make([]int64, 0, len(byBucket))
	for key := range byBucket {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	result := CatalogTraffic{Samples: make([]metrics.Sample, 0, len(keys)), Entries: used}
	for _, key := range keys {
		result.Samples = append(result.Samples, byBucket[key])
	}
	return result, nil
}

// ReadCatalogDetections reads only provenance-owned detections from registered
// isolated results. It never opens or queries a configured live database.
func ReadCatalogDetections(ctx context.Context, catalogPath string, from, to time.Time, limit int) ([]CatalogDetection, error) {
	if !from.Before(to) || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("ordered detection range and limit 1-1000 are required")
	}
	entries, err := CatalogEntries(ctx, catalogPath)
	if err != nil {
		return nil, err
	}
	result := []CatalogDetection{}
	for _, entry := range entries {
		if !entry.From.Before(to) || !from.Before(entry.To) {
			continue
		}
		candidate, err := catalogCandidate(ctx, entry.ResultPath)
		if err != nil {
			return nil, fmt.Errorf("verify catalog import %s: %w", entry.ImportID, err)
		}
		if candidate.SHA256 != entry.SHA256 || candidate.ImportID != entry.ImportID {
			return nil, fmt.Errorf("catalog import %s no longer matches its registered result", entry.ImportID)
		}
		reader, err := storage.OpenReader(entry.ResultPath)
		if err != nil {
			return nil, err
		}
		detections, readErr := reader.HistoricalDetectionsRange(ctx, entry.ImportID, maxTime(from, entry.From), minTime(to, entry.To), limit)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		for _, detection := range detections {
			result = append(result, CatalogDetection{ImportID: entry.ImportID, HistoricalDetection: detection})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].EventTime.Equal(result[j].EventTime) {
			if result[i].ImportID == result[j].ImportID {
				return result[i].ID < result[j].ID
			}
			return result[i].ImportID < result[j].ImportID
		}
		return result[i].EventTime.Before(result[j].EventTime)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func PublishToCatalog(ctx context.Context, catalogPath, resultPath string) (CatalogResult, error) {
	if !filepath.IsAbs(catalogPath) || !filepath.IsAbs(resultPath) {
		return CatalogResult{}, fmt.Errorf("catalog and result paths must be absolute")
	}
	if filepath.Clean(catalogPath) == filepath.Clean(resultPath) {
		return CatalogResult{}, fmt.Errorf("catalog must not be a result database")
	}
	if err := validateCatalogPath(catalogPath, true); err != nil {
		return CatalogResult{}, err
	}
	entry, err := catalogCandidate(ctx, resultPath)
	if err != nil {
		return CatalogResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o700); err != nil {
		return CatalogResult{}, err
	}
	db, err := sql.Open("sqlite3", "file:"+filepath.Clean(catalogPath))
	if err != nil {
		return CatalogResult{}, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err = createCatalogSchema(ctx, db); err != nil {
		return CatalogResult{}, fmt.Errorf("create history catalog: %w", err)
	}
	if err = os.Chmod(catalogPath, 0o600); err != nil {
		return CatalogResult{}, fmt.Errorf("restrict history catalog permissions: %w", err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return CatalogResult{}, err
	}
	defer tx.Rollback()
	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT import_id FROM history_catalog_entries WHERE import_id=? OR result_path=? OR result_sha256=?`, entry.ImportID, entry.ResultPath, entry.SHA256).Scan(&existingID)
	if err == nil {
		if existingID != entry.ImportID {
			return CatalogResult{}, fmt.Errorf("catalog identity collision with import %s", existingID)
		}
		if err := tx.Commit(); err != nil {
			return CatalogResult{}, err
		}
		return CatalogResult{Entry: entry, AlreadyPublished: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CatalogResult{}, err
	}
	var overlap string
	err = tx.QueryRowContext(ctx, `SELECT import_id FROM history_catalog_entries WHERE source_id=? AND period_from_unix_ns<? AND period_to_unix_ns>? LIMIT 1`, entry.SourceID, entry.To.UnixNano(), entry.From.UnixNano()).Scan(&overlap)
	if err == nil {
		return CatalogResult{}, fmt.Errorf("coverage overlaps catalog import %s", overlap)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CatalogResult{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO history_catalog_entries VALUES(?,?,?,?,?,?,?,?)`, entry.ImportID, entry.ResultPath, entry.SHA256, entry.SourceID, entry.AnalysisConfigID, entry.From.UnixNano(), entry.To.UnixNano(), entry.CreatedAt.UnixMilli())
	if err != nil {
		return CatalogResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CatalogResult{}, err
	}
	return CatalogResult{Entry: entry}, nil
}

// ReplaceCatalog is an explicit, metadata-only ownership replacement. The
// prior result file is never deleted. Replacement requires the same source and
// analysis identity plus an overlapping interval, then checks every remaining
// catalog entry before committing the delete+insert atomically.
func ReplaceCatalog(ctx context.Context, catalogPath, resultPath, replaceImportID string) (CatalogResult, error) {
	if replaceImportID == "" {
		return CatalogResult{}, fmt.Errorf("replacement import ID is required")
	}
	entry, err := catalogCandidate(ctx, resultPath)
	if err != nil {
		return CatalogResult{}, err
	}
	db, err := openCatalog(ctx, catalogPath, resultPath)
	if err != nil {
		return CatalogResult{}, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return CatalogResult{}, err
	}
	defer tx.Rollback()
	var oldSource, oldConfig string
	var oldFrom, oldTo int64
	if err := tx.QueryRowContext(ctx, `SELECT source_id,analysis_config_id,period_from_unix_ns,period_to_unix_ns FROM history_catalog_entries WHERE import_id=?`, replaceImportID).Scan(&oldSource, &oldConfig, &oldFrom, &oldTo); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CatalogResult{}, fmt.Errorf("catalog import %s not found", replaceImportID)
		}
		return CatalogResult{}, err
	}
	if entry.SourceID != oldSource || entry.AnalysisConfigID != oldConfig {
		return CatalogResult{}, fmt.Errorf("replacement must keep source and analysis identity")
	}
	if !entry.From.Before(time.Unix(0, oldTo)) || !time.Unix(0, oldFrom).Before(entry.To) {
		return CatalogResult{}, fmt.Errorf("replacement period must overlap the existing ownership")
	}
	var conflict string
	err = tx.QueryRowContext(ctx, `SELECT import_id FROM history_catalog_entries WHERE import_id<>? AND source_id=? AND period_from_unix_ns<? AND period_to_unix_ns>? LIMIT 1`, replaceImportID, entry.SourceID, entry.To.UnixNano(), entry.From.UnixNano()).Scan(&conflict)
	if err == nil {
		return CatalogResult{}, fmt.Errorf("replacement overlaps catalog import %s", conflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CatalogResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM history_catalog_entries WHERE import_id=?`, replaceImportID); err != nil {
		return CatalogResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO history_catalog_entries VALUES(?,?,?,?,?,?,?,?)`, entry.ImportID, entry.ResultPath, entry.SHA256, entry.SourceID, entry.AnalysisConfigID, entry.From.UnixNano(), entry.To.UnixNano(), entry.CreatedAt.UnixMilli()); err != nil {
		return CatalogResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CatalogResult{}, err
	}
	return CatalogResult{Entry: entry}, nil
}

func openCatalog(ctx context.Context, catalogPath, resultPath string) (*sql.DB, error) {
	if !filepath.IsAbs(catalogPath) || !filepath.IsAbs(resultPath) {
		return nil, fmt.Errorf("catalog and result paths must be absolute")
	}
	if filepath.Clean(catalogPath) == filepath.Clean(resultPath) {
		return nil, fmt.Errorf("catalog must not be a result database")
	}
	if err := validateCatalogPath(catalogPath, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "file:"+filepath.Clean(catalogPath))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := createCatalogSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(catalogPath, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict history catalog permissions: %w", err)
	}
	return db, nil
}

func validateCatalogPath(catalogPath string, allowMissing bool) error {
	info, err := os.Lstat(catalogPath)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect history catalog: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("catalog must be a regular file")
	}
	return nil
}

func createCatalogSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS history_catalog_entries(import_id TEXT PRIMARY KEY,result_path TEXT NOT NULL UNIQUE,result_sha256 TEXT NOT NULL UNIQUE,source_id TEXT NOT NULL,analysis_config_id TEXT NOT NULL,period_from_unix_ns INTEGER NOT NULL,period_to_unix_ns INTEGER NOT NULL,created_at_unix_ms INTEGER NOT NULL, CHECK(period_to_unix_ns>period_from_unix_ns)); CREATE INDEX IF NOT EXISTS history_catalog_period_idx ON history_catalog_entries(source_id,period_from_unix_ns,period_to_unix_ns)`)
	if err != nil {
		return fmt.Errorf("create history catalog: %w", err)
	}
	return nil
}

func catalogCandidate(ctx context.Context, resultPath string) (CatalogEntry, error) {
	info, err := os.Lstat(resultPath)
	if err != nil {
		return CatalogEntry{}, err
	}
	if !info.Mode().IsRegular() {
		return CatalogEntry{}, fmt.Errorf("result must be a regular file")
	}
	file, err := os.Open(resultPath)
	if err != nil {
		return CatalogEntry{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return CatalogEntry{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return CatalogEntry{}, fmt.Errorf("result changed after validation")
	}
	reader, err := storage.OpenReader(resultPath)
	if err != nil {
		return CatalogEntry{}, err
	}
	imports, readErr := reader.HistoryImports(ctx)
	var comparisonRule string
	if readErr == nil && len(imports) == 1 {
		if document, err := reader.HistoryImportManifest(ctx, imports[0].ID); err == nil {
			var manifest struct {
				ComparisonRule string `json:"comparison_rule"`
			}
			if err := json.Unmarshal(document, &manifest); err != nil {
				readErr = err
			} else {
				comparisonRule = manifest.ComparisonRule
			}
		} else {
			readErr = err
		}
	}
	closeErr := reader.Close()
	if readErr != nil {
		return CatalogEntry{}, readErr
	}
	if closeErr != nil {
		return CatalogEntry{}, closeErr
	}
	if len(imports) != 1 {
		return CatalogEntry{}, fmt.Errorf("result must contain exactly one import")
	}
	if comparisonRule != "" {
		return CatalogEntry{}, fmt.Errorf("comparison result for rule %q cannot be published", comparisonRule)
	}
	item := imports[0]
	if !item.HasRequestedPeriod || item.AnalysisConfigID == "" {
		return CatalogEntry{}, fmt.Errorf("result requires an observed or explicit period and analysis identity")
	}
	// Inferred ranges begin at the first observed event and end immediately
	// after the last. Claim complete traffic buckets for overlap protection.
	interval := int64(metrics.SampleInterval / time.Second)
	fromUnix := item.RequestedFrom.Unix() / interval * interval
	toUnix := (item.RequestedTo.Unix() + interval - 1) / interval * interval
	if item.RequestedTo.UnixNano()%int64(time.Second) != 0 && item.RequestedTo.Unix()%interval == 0 {
		toUnix += interval
	}
	item.RequestedFrom, item.RequestedTo = time.Unix(fromUnix, 0), time.Unix(toUnix, 0)
	hash := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return CatalogEntry{}, err
	}
	if _, err := io.Copy(hash, file); err != nil {
		return CatalogEntry{}, err
	}
	final, err := os.Lstat(resultPath)
	if err != nil || !final.Mode().IsRegular() || !os.SameFile(opened, final) || final.Size() != opened.Size() || !final.ModTime().Equal(opened.ModTime()) {
		return CatalogEntry{}, fmt.Errorf("result changed while being cataloged")
	}
	return CatalogEntry{item.ID, resultPath, fmt.Sprintf("%x", hash.Sum(nil)), item.SourceID, item.AnalysisConfigID, item.RequestedFrom, item.RequestedTo, time.Now().UTC()}, nil
}
