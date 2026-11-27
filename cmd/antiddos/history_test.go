package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/storage"
)

func TestHistoryRunUsesConfiguredRulesAndRecordsBackdatedDetections(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "archives")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := `192.0.2.25 - - [01/Jan/2024:00:00:01 +0000] "GET /login HTTP/1.1" 401 12 "-" "scanner"` + "\n" +
		`192.0.2.25 - - [01/Jan/2024:00:00:02 +0000] "GET /login HTTP/1.1" 401 12 "-" "scanner"` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "site-access.log.1.gz"), gzipBytes(t, contents), 0o600); err != nil {
		t.Fatal(err)
	}
	liveDB := filepath.Join(root, "antiddos.sqlite")
	configFile := filepath.Join(root, "config.json")
	document := `{"log_sources":{"web":{"path":"/var/log/nginx/site-access.log","format":"nginx_combined"}},"database_path":"` + liveDB + `","block_mode":"nftables","block_tcp_ports":[80],"engine":{"rules":[{"id":"configured-login-rule","log_source":"web","path_regex":"^/login$","statuses":[401],"window":"10s","threshold":2,"group_by":"ip"}]}}`
	if err := os.WriteFile(configFile, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := executeCommand(context.Background(), []string{
		"history", "run", "--config", configFile,
		"--directory", logs, "--name-regex", `^site-access\.log(?:\.[0-9]+)?\.gz$`,
		"--work-directory", root, "--sort-memory-bytes", "256", "--max-sort-bytes", "1048576",
	}, slog.Default(), &output)
	if err != nil {
		t.Fatalf("history run: %v\n%s", err, output.String())
	}
	for _, expected := range []string{"configured-login-rule", "detections=1", "Enforcement is disabled", "2024-01-01"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q:\n%s", expected, output.String())
		}
	}
	db, err := sql.Open("sqlite3", liveDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var eventNS int64
	var ruleID, sourceID string
	var dryRun bool
	if err := db.QueryRow(`SELECT event_time_unix_ns,rule_id,log_source,dry_run FROM detections`).Scan(&eventNS, &ruleID, &sourceID, &dryRun); err != nil {
		t.Fatal(err)
	}
	wantEvent := time.Date(2024, 1, 1, 0, 0, 2, 0, time.UTC)
	if eventNS != wantEvent.UnixNano() || ruleID != "configured-login-rule" || sourceID != "web" || !dryRun {
		t.Fatalf("stored detection = time %s rule %q source %q dry-run %t", time.Unix(0, eventNS), ruleID, sourceID, dryRun)
	}
	var blocks, imports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM active_blocks`).Scan(&blocks); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM history_imports`).Scan(&imports); err != nil {
		t.Fatal(err)
	}
	if blocks != 0 || imports != 1 {
		t.Fatalf("blocks=%d imports=%d", blocks, imports)
	}
	output.Reset()
	if err := executeCommand(context.Background(), []string{
		"history", "run", "--config", configFile,
		"--directory", logs, "--name-regex", `^site-access\.log(?:\.[0-9]+)?\.gz$`,
		"--work-directory", root, "--sort-memory-bytes", "256", "--max-sort-bytes", "1048576",
	}, slog.Default(), &output); err != nil {
		t.Fatalf("idempotent rerun: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "already recorded") || !strings.Contains(output.String(), "no rows were duplicated") {
		t.Fatalf("rerun output = %s", output.String())
	}
	var detections int
	if err := db.QueryRow(`SELECT COUNT(*) FROM detections`).Scan(&detections); err != nil {
		t.Fatal(err)
	}
	if detections != 1 {
		t.Fatalf("detections after rerun = %d", detections)
	}
	leftovers, err := filepath.Glob(filepath.Join(root, ".antiddos-history-result-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary results = %v, %v", leftovers, err)
	}
}

func TestHistoryRunRequiresTwoExplicitArchiveEnforcementFlags(t *testing.T) {
	for _, args := range [][]string{{"history", "run", "--apply-blocks"}, {"history", "run", "--confirm-archive-blocks"}} {
		var output bytes.Buffer
		err := executeCommand(context.Background(), args, slog.Default(), &output)
		if err == nil || !strings.Contains(err.Error(), "requires both") {
			t.Fatalf("args %v error=%v", args, err)
		}
	}
}

func TestHistoryRunAppliesOneBlockForHundredArchiveEventsFromOneIP(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "archives")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	var contents strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprint(&contents, "198.51.100.77 - - [01/Jan/2024:00:00:01 +0000] \"GET /attack HTTP/1.1\" 404 12 \"-\" \"archive-test\"\n")
	}
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(contents.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	liveDB := filepath.Join(root, "antiddos.sqlite")
	configFile := filepath.Join(root, "config.json")
	document := `{"log_sources":{"web":{"path":"/unused/access.log","format":"nginx_combined"}},"database_path":"` + liveDB + `","block_mode":"dry_run","block_duration":"5m","engine":{"rules":[{"id":"archive-flood","action":"nftables","block_duration":"720h","log_source":"web","path_regex":"^/attack$","statuses":[404],"window":"2m","threshold":100,"group_by":"ip"}]}}`
	if err := os.WriteFile(configFile, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &historyTestAction{}
	originalActions := historicalFirewallActions
	historicalFirewallActions = func(config.Config) (action.Action, action.Action) { return fake, fake }
	t.Cleanup(func() { historicalFirewallActions = originalActions })
	var output bytes.Buffer
	err := executeCommand(context.Background(), []string{
		"history", "run", "--config", configFile, "--source", "web", "--directory", logs,
		"--name-regex", `^access\.log$`, "--work-directory", root, "--sort-memory-bytes", "256", "--max-sort-bytes", "1048576",
		"--apply-blocks", "--confirm-archive-blocks",
	}, slog.Default(), &output)
	if err != nil {
		t.Fatalf("history run: %v\\n%s", err, output.String())
	}
	if fake.applied != 1 || fake.request.IP != netip.MustParseAddr("198.51.100.77") || fake.request.RuleID != "archive-flood" {
		t.Fatalf("firewall requests = %d, request = %#v", fake.applied, fake.request)
	}
	if remaining := time.Until(fake.request.ExpiresAt); remaining < 719*time.Hour || remaining > 721*time.Hour {
		t.Fatalf("block duration remaining = %s, want about 720h", remaining)
	}
	db, err := sql.Open("sqlite3", liveDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var blocks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM active_blocks WHERE ip = '198.51.100.77' AND rule_id = 'archive-flood'`).Scan(&blocks); err != nil {
		t.Fatal(err)
	}
	if blocks != 1 || !strings.Contains(output.String(), "Historical enforcement applied: 1 new firewall blocks") {
		t.Fatalf("blocks=%d output=%s", blocks, output.String())
	}
}

type historyTestAction struct {
	applied int
	request action.BlockRequest
}

func (testAction *historyTestAction) Apply(_ context.Context, request action.BlockRequest) action.Result {
	testAction.applied++
	testAction.request = request
	return action.Result{Status: action.StatusApplied, IP: request.IP, ExpiresAt: request.ExpiresAt}
}

func (testAction *historyTestAction) Remove(context.Context, netip.Addr) action.Result {
	return action.Result{Status: action.StatusAlreadyAbsent, IP: netip.MustParseAddr("198.51.100.77")}
}

func gzipBytes(t *testing.T, value string) []byte {
	t.Helper()
	var result bytes.Buffer
	writer := gzip.NewWriter(&result)
	if _, err := writer.Write([]byte(value)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestHistoryPreviewCommandIsReadOnlyAndDescribesRegexScope(t *testing.T) {
	directory := t.TempDir()
	line := `192.0.2.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "test"` + "\n"
	if err := os.WriteFile(filepath.Join(directory, "access.log"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := executeCommand(context.Background(), []string{
		"history", "preview", "--directory", directory, "--name-regex", `^access\.log$`,
	}, slog.Default(), &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"access.log", "parsed 1, ignored 0, malformed 0 of 1 lines", "base filename (not the path)", "No data was imported"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestPreflightCoverageRejectsOverlapAndAcceptsAdjacent(t *testing.T) {
	base := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	makeCandidate := func(database string, from, to time.Time) coverageCandidate {
		return coverageCandidate{database: database, item: storage.HistoryImportSummary{SourceID: "web", AnalysisConfigID: "same", HasRequestedPeriod: true, WarmupComplete: true, RequestedFrom: from, RequestedTo: to}}
	}
	if err := preflightCoverage([]coverageCandidate{makeCandidate("a", base, base.Add(time.Hour)), makeCandidate("b", base.Add(30*time.Minute), base.Add(2*time.Hour))}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlap error = %v", err)
	}
	if err := preflightCoverage([]coverageCandidate{makeCandidate("a", base, base.Add(time.Hour)), makeCandidate("b", base.Add(time.Hour), base.Add(2*time.Hour))}); err != nil {
		t.Fatalf("adjacent coverage: %v", err)
	}
}

func TestHistoryPreviewRequiresExplicitSyslogTimeContext(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "auth.log"), []byte("Oct 26 13:20:01 host sshd[1]: Failed password for root from 198.51.100.8 port 22 ssh2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := executeCommand(context.Background(), []string{
		"history", "preview", "--directory", directory, "--name-regex", `^auth\.log$`, "--format", "syslog_sshd",
	}, slog.Default(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "explicit timezone and syslog year") {
		t.Fatalf("error = %v", err)
	}
}

func TestHistoryDetectionsCommandShowsWhoWhenAndRule(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `192.0.2.1 - - [01/Jan/2024:00:00:05 +0000] "GET /login HTTP/1.1" 200 12 "-" "test"` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "config.json")
	configText := `{"log_sources":{"web":"/unused/live.log"},"database_path":"` + filepath.Join(root, "live.sqlite") + `","engine":{"rules":[{"id":"login","log_source":"web","path_regex":"^/login$","window":"1s","threshold":1,"group_by":"ip"}]}}`
	if err := os.WriteFile(configFile, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "isolated.sqlite")
	args := []string{"history", "import", "--config", configFile, "--source", "web", "--directory", logs, "--name-regex", `^access\.log$`, "--output", output, "--temp-directory", root}
	if err := executeCommand(context.Background(), args, slog.Default(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var report bytes.Buffer
	if err := historyDetectionsCommand(context.Background(), []string{"--database", output, "--limit", "1"}, &report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"192.0.2.1", "login", "/login", "2024-01-01", "Total: 1"} {
		if !strings.Contains(report.String(), expected) {
			t.Fatalf("missing %q: %s", expected, report.String())
		}
	}
}

func TestHistoryImportCommandPublishesOnlyIsolatedOutput(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	line := `192.0.2.1 - - [01/Jan/2024:00:00:00 +0000] "GET /login HTTP/1.1" 200 12 "-" "test"` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	liveDB := filepath.Join(root, "live.sqlite")
	configFile := filepath.Join(root, "config.json")
	document := `{"log_sources":{"web":{"path":"/unused/live.log","format":"nginx_combined"}},"database_path":"` + liveDB + `","block_mode":"dry_run","engine":{"rules":[{"id":"login","log_source":"web","path_regex":"^/login$","window":"1s","threshold":1,"group_by":"ip"}]}}`
	if err := os.WriteFile(configFile, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "history.sqlite")
	var printed bytes.Buffer
	err := executeCommand(context.Background(), []string{
		"history", "import", "--config", configFile, "--source", "web", "--directory", logs,
		"--name-regex", `^access\.log$`, "--output", output, "--sort-memory-bytes", "256", "--max-sort-bytes", "1048576",
	}, slog.Default(), &printed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed.String(), "actions and live database are disabled") || !strings.Contains(printed.String(), "detections: 1") {
		t.Fatalf("output = %s", printed.String())
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(liveDB); !os.IsNotExist(err) {
		t.Fatalf("live database was touched: %v", err)
	}
	var report bytes.Buffer
	if err := executeCommand(context.Background(), []string{"history", "report", "--database", output}, slog.Default(), &report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Source: web", "Files: 1; lines: 1; parsed: 1", "Import ID:", "Requested period:", "complete: false"} {
		if !strings.Contains(report.String(), expected) {
			t.Fatalf("report missing %q: %s", expected, report.String())
		}
	}
}

func TestParseHistoryPeriodRequiresBothOrderedRFC3339Bounds(t *testing.T) {
	if _, _, err := parseHistoryPeriod("2024-01-01T00:00:00Z", ""); err == nil {
		t.Fatal("one-sided period was accepted")
	}
	if _, _, err := parseHistoryPeriod("bad", "2024-01-02T00:00:00Z"); err == nil {
		t.Fatal("malformed period was accepted")
	}
	if _, _, err := parseHistoryPeriod("2024-01-02T00:00:00Z", "2024-01-01T00:00:00Z"); err == nil {
		t.Fatal("reversed period was accepted")
	}
	from, to, err := parseHistoryPeriod("2024-01-01T00:00:00+07:00", "2024-01-02T00:00:00+07:00")
	if err != nil || !from.Before(to) {
		t.Fatalf("period = %v, %v, %v", from, to, err)
	}
}
