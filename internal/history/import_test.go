package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/storage"
)

func TestOneLineResponseTimePublishedToDashboard(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	line := nginxLine("13/Oct/2026:07:00:11 +0700", "/login") + ` "0.048" "example.test"` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(root, "result.sqlite")
	result, err := Import(context.Background(), importTestOptions(logs, resultPath))
	if err != nil {
		t.Fatal(err)
	}
	livePath := filepath.Join(root, "live.sqlite")
	if _, err := PublishToDatabase(context.Background(), resultPath, livePath, result.ImportID); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertSQLCount(t, db, "SELECT COALESCE(SUM(rows),0) FROM response_time_samples", 1)
	assertSQLCount(t, db, "SELECT MAX(max_ms) FROM response_time_samples", 48)
	reader, err := storage.OpenReader(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	from := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	dashboard, err := reader.Dashboard(context.Background(), from, from.Add(24*time.Hour), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var maxMS int64
	for _, point := range dashboard.Points {
		if point.ResponseTimeMaxMS > maxMS {
			maxMS = point.ResponseTimeMaxMS
		}
	}
	if maxMS != 48 {
		t.Fatalf("dashboard max response time = %d ms, want 48 ms", maxMS)
	}
}

func TestImportPreflightAndWorkDirectoryFailureLeaveNoOutput(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(nginxLine("01/Jan/2024:00:00:01 +0000", "/login")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "result.sqlite")
	options := importTestOptions(logs, output)
	if err := preflightWorkspace(root, 1<<62); err == nil || !strings.Contains(err.Error(), "insufficient free space") {
		t.Fatalf("preflight: %v", err)
	}
	workFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(workFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	options.TempDirectory = workFile
	_, err := Import(context.Background(), options)
	if err == nil {
		t.Fatal("expected work directory failure")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("output created after work directory failure: %v", statErr)
	}
}

func TestImportGloballySortsAndAtomicallyPublishesIsolatedDatabase(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	// Physical order is deliberately not event order and the ranges overlap.
	older := nginxLine("01/Jan/2024:00:00:03 +0000", "/login") + "\n" + nginxLine("01/Jan/2024:00:00:01 +0000", "/login") + "\n"
	newer := nginxLine("01/Jan/2024:00:00:02 +0000", "/login") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log.1"), []byte(older), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(newer), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "history.sqlite")
	result, err := Import(context.Background(), importTestOptions(logs, output))
	if err != nil {
		t.Fatal(err)
	}
	if result.Parsed != 3 || result.Detections != 2 || result.Malformed != 0 || result.ImportID == "" {
		t.Fatalf("result = %+v", result)
	}
	if result.FirstEvent.Unix() >= result.LastEvent.Unix() {
		t.Fatalf("event range = %v to %v", result.FirstEvent, result.LastEvent)
	}
	db, err := sql.Open("sqlite3", output)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertSQLCount(t, db, "SELECT COUNT(*) FROM detections", 2)
	assertSQLCount(t, db, "SELECT COALESCE(SUM(requests),0) FROM traffic_samples", 3)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM history_imports", 1)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM history_detection_provenance", 2)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM history_traffic_samples", 1)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM history_coverage", 1)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM active_blocks", 0)
	if _, err := Import(context.Background(), importTestOptions(logs, output)); err == nil {
		t.Fatal("second import overwrote an existing published database")
	}
}

func TestImportMalformedInputLeavesNoPublishedDatabase(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	contents := nginxLine("01/Jan/2024:00:00:01 +0000", "/login") + "\nmalformed\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "history.sqlite")
	if _, err := Import(context.Background(), importTestOptions(logs, output)); err == nil {
		t.Fatal("malformed input was imported without explicit allowance")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed import published output: %v", err)
	}
}

func TestImportPeriodWarmsRulesAndPublishesOnlyHalfOpenRange(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	contents := nginxLine(base.Format("02/Jan/2006:15:04:05 -0700"), "/health") + "\n" +
		nginxLine(base.Add(5*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(10*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(20*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "period.sqlite")
	options := importTestOptions(logs, output)
	options.From = base.Add(10 * time.Second)
	options.To = base.Add(20 * time.Second)
	result, err := Import(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Published != 1 || result.Warmup != 2 || result.Detections != 1 || !result.WarmupComplete {
		t.Fatalf("result = %+v", result)
	}
	db, err := sql.Open("sqlite3", output)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertSQLCount(t, db, "SELECT COALESCE(SUM(requests),0) FROM traffic_samples", 1)
	assertSQLCount(t, db, "SELECT COUNT(*) FROM detections", 1)
	var eventTime int64
	if err := db.QueryRow("SELECT event_time_unix_ns FROM detections").Scan(&eventTime); err != nil {
		t.Fatal(err)
	}
	if eventTime != options.From.UnixNano() {
		t.Fatalf("detection time = %d, want %d", eventTime, options.From.UnixNano())
	}
	var manifestText string
	if err := db.QueryRow("SELECT manifest_json FROM history_imports").Scan(&manifestText); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(manifestText), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["from"] != options.From.Format(time.RFC3339Nano) || manifest["to"] != options.To.Format(time.RFC3339Nano) || manifest["warmup_complete"] != true {
		t.Fatalf("manifest = %#v", manifest)
	}
	var requestedFrom, requestedTo int64
	var requested, warmupComplete bool
	if err := db.QueryRow("SELECT has_requested_period,requested_from_unix_ns,requested_to_unix_ns,warmup_complete FROM history_coverage").Scan(&requested, &requestedFrom, &requestedTo, &warmupComplete); err != nil {
		t.Fatal(err)
	}
	if !requested || requestedFrom != options.From.UnixNano() || requestedTo != options.To.UnixNano() || !warmupComplete {
		t.Fatalf("coverage = requested=%t from=%d to=%d warmup=%t", requested, requestedFrom, requestedTo, warmupComplete)
	}
	rules, ok := manifest["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("manifest rules = %#v", manifest["rules"])
	}
}

func TestImportPeriodReportsIncompleteWarmup(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	line := nginxLine(base.Add(10*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	options := importTestOptions(logs, filepath.Join(root, "period.sqlite"))
	options.From = base.Add(10 * time.Second)
	options.To = base.Add(20 * time.Second)
	result, err := Import(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.WarmupComplete {
		t.Fatalf("warm-up unexpectedly complete: %+v", result)
	}
}

func TestImportPeriodRequiresBothOrderedBounds(t *testing.T) {
	options := importTestOptions(t.TempDir(), filepath.Join(t.TempDir(), "history.sqlite"))
	options.From = time.Now()
	if _, err := Import(context.Background(), options); err == nil {
		t.Fatal("period with only from was accepted")
	}
	options.To = options.From
	if _, err := Import(context.Background(), options); err == nil {
		t.Fatal("empty period was accepted")
	}
}

func importTestOptions(directory, output string) ImportOptions {
	return ImportOptions{
		Config: config.Config{
			LogSources: []config.LogSourceConfig{{ID: "web", Path: "/unused/live.log", Format: config.LogFormatNginxCombined}},
			Engine: config.EngineConfig{Rules: []config.RuleConfig{{
				ID: "login", Enabled: true, LogSource: "web", Type: "rate", PathRegex: `^/login$`,
				Window: 10 * time.Second, Threshold: 2, GroupBy: "ip",
			}}},
		},
		SourceID: "web", Directory: directory, NameRegex: `^access\.log(?:\.[0-9]+)?$`, OutputPath: output,
		Order: OrderNatural, MaxFiles: 10, MaxInputBytes: 1 << 20, MaxExpandedBytes: 1 << 20, MaxLineBytes: 64 << 10,
		SortMemoryBytes: 200, MaxSortBytes: 1 << 20, TempDirectory: filepath.Dir(output), AllowMalformed: 0,
	}
}

func assertSQLCount(t *testing.T, db *sql.DB, query string, want int64) {
	t.Helper()
	var got int64
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", query, got, want)
	}
}
