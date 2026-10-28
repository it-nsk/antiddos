package challenge

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsAdminEndpointAndFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(metricBucket)
	m, err := openMetrics(filepath.Join(t.TempDir(), "metrics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	m.record(now, "bgt", metricIssued)
	if err := m.flush(now); err != nil {
		t.Fatal(err)
	}
	service := &Service{metrics: m}
	request := httptest.NewRequest(http.MethodGet, "/v1/metrics?from="+now.Add(-time.Minute).Format(time.RFC3339)+"&to="+now.Add(time.Minute).Format(time.RFC3339)+"&limit=10", nil)
	response := httptest.NewRecorder()
	service.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"reason":"issued"`) {
		t.Fatalf("response %d: %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	service.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/metrics?from=bad&to=bad&limit=1001", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid query status %d", response.Code)
	}
	if err := m.close(); err != nil {
		t.Fatal(err)
	}
	m.record(now, "bgt", metricSolved)
	if err := m.flush(now); err == nil || m.dropped() != 1 {
		t.Fatalf("failure err=%v lost=%d", err, m.dropped())
	}
}

func TestMetricsBatchPersistenceAndRetention(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 6, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "metrics.sqlite")
	m, err := openMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	m.record(now, "bgt", metricIssued)
	m.record(now.Add(time.Second), "bgt", metricIssued)
	m.record(now, "bgt", metricSolved)
	if err := m.flush(now); err != nil {
		t.Fatal(err)
	}
	if err := m.close(); err != nil {
		t.Fatal(err)
	}
	m, err = openMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	rows, err := m.query(now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Count != 2 || rows[0].Reason != metricIssued || rows[0].Bucket != now.Truncate(metricBucket).Unix() || rows[1].Count != 1 || rows[1].Reason != metricSolved {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if err := m.flush(now.Add(8 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err = m.query(now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("retention: rows=%+v err=%v", rows, err)
	}
}

func TestMetricsBoundedAndRejectsUntrustedDimensions(t *testing.T) {
	m, err := openMetrics(filepath.Join(t.TempDir(), "metrics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	now := time.Now()
	for i := 0; i < maxMetricKeys+1; i++ {
		m.record(now.Add(time.Duration(i)*metricBucket), "bgt", metricIssued)
	}
	m.record(now, "bgt", "untrusted")
	if m.dropped() != 2 {
		t.Fatalf("dropped = %d", m.dropped())
	}
}

func TestMetricsKeepsLegacyFifteenSecondBucketsReadable(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	m, err := openMetrics(filepath.Join(t.TempDir(), "metrics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	legacyBucket := now.Add(-15 * time.Second).Unix()
	if _, err := m.db.Exec(`INSERT INTO metrics(bucket,site,reason,count) VALUES(?,?,?,?)`, legacyBucket, "bgt", metricIssued, 7); err != nil {
		t.Fatal(err)
	}
	m.record(now.Add(time.Second), "bgt", metricSolved)
	if err := m.flush(now.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rows, err := m.query(now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Bucket != legacyBucket || rows[0].Count != 7 || rows[1].Bucket != now.Unix() {
		t.Fatalf("mixed legacy/new rows=%+v", rows)
	}
}
