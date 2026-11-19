package webui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/history"
	"github.com/it-nsk/antiddos/internal/webauth"
)

func TestManagedHistoryRequiresCompleteBoundary(t *testing.T) {
	if _, err := newHistoryJobs("/tmp/config.json", "", []string{"/tmp"}); err == nil {
		t.Fatal("incomplete managed-history boundary accepted")
	}
}

func TestManagedHistoryMarksUnfinishedJobInterruptedOnRestart(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	output := filepath.Join(root, "output")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef01234567"
	jobs := []HistoryJob{{ID: id, State: "running", CreatedAt: time.Now().UTC(), Request: HistoryJobRequest{SourceID: "default", Directory: logs, NameRegex: `^access\.log$`}, OutputPath: expectedHistoryOutputPath(output, id)}}
	encoded, err := json.Marshal(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, historyJobsStateFile), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := newHistoryJobs(filepath.Join(root, "config.json"), output, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := m.get(id)
	if !ok || loaded.State != "interrupted" || loaded.FinishedAt == nil {
		t.Fatalf("restored job = %#v, exists=%t", loaded, ok)
	}
	persisted, err := os.ReadFile(filepath.Join(output, historyJobsStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), `"interrupted"`) {
		t.Fatalf("state was not persisted: %s", persisted)
	}
}

func TestManagedHistoryPreviewOnlyReturnsBaseNames(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(`192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "test"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"log_file":"`+filepath.Join(root, "live.log")+`","database_path":"`+filepath.Join(root, "live.sqlite")+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := newHistoryJobs(configPath, filepath.Join(root, "output"), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := m.preview(context.Background(), HistoryJobRequest{SourceID: "default", Directory: logs, NameRegex: `^access\.log$`})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Files) != 1 || preview.Files[0].Name != "access.log" || preview.Files[0].Parsed != 1 {
		t.Fatalf("preview = %#v", preview)
	}
}

func TestManagedHistoryRejectsDirectoryOutsideRootsBeforeQueueing(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	m, err := newHistoryJobs(filepath.Join(root, "config.json"), output, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.start(HistoryJobRequest{SourceID: "web", Directory: filepath.Dir(root), NameRegex: `^access\\.log$`})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside directory error = %v", err)
	}
	if jobs := m.list(); len(jobs) != 0 {
		t.Fatalf("unexpected queued jobs: %#v", jobs)
	}
}

func TestManagedHistoryRejectsImplicitPublish(t *testing.T) {
	root := t.TempDir()
	m, err := newHistoryJobs(filepath.Join(root, "config.json"), filepath.Join(root, "output"), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.start(HistoryJobRequest{SourceID: "web", Directory: root, NameRegex: "^access\\.log$", Publish: true})
	if err == nil || !strings.Contains(err.Error(), "separate explicit action") {
		t.Fatalf("implicit publish: %v", err)
	}
	if len(m.list()) != 0 {
		t.Fatal("implicit publish queued a job")
	}
}

func TestComparisonResultCannotPublish(t *testing.T) {
	root := t.TempDir()
	m, err := newHistoryJobs(filepath.Join(root, "config.json"), filepath.Join(root, "output"), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef01234567"
	m.jobs[id] = &HistoryJob{ID: id, State: "published", Request: HistoryJobRequest{ComparisonRule: "login"}, Result: &history.ImportResult{ImportID: "isolated"}}
	if _, err := m.publish(context.Background(), id); err == nil || !strings.Contains(err.Error(), "comparison results cannot be published") {
		t.Fatalf("publish comparison: %v", err)
	}
}

func TestManagedHistoryImportAndRuleComparison(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `192.0.2.1 - - [01/Jan/2024:00:00:05 +0000] "GET /login HTTP/1.1" 200 1 "-" "test"` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line+line), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	document := `{"log_sources":{"web":"` + filepath.Join(root, "live.log") + `"},"database_path":"` + filepath.Join(root, "live.sqlite") + `","engine":{"rules":[{"id":"login","log_source":"web","path_regex":"^/login$","window":"10s","threshold":2,"group_by":"ip"}]}}`
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := newHistoryJobs(configPath, filepath.Join(root, "results"), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	m.nice, m.ioPriority = 10, 7
	request := HistoryJobRequest{SourceID: "web", Directory: logs, NameRegex: `^access\.log$`, AllowMalformed: 0}
	preview, err := m.preview(context.Background(), request)
	if err != nil || preview.Parsed != 2 || preview.EstimatedBytes == 0 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	job, err := m.start(request)
	if err != nil {
		t.Fatal(err)
	}
	waitDone := func(id string) HistoryJob {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			current, _ := m.get(id)
			if current.State != "queued" && current.State != "running" {
				return current
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("historical job timed out")
		return HistoryJob{}
	}
	first := waitDone(job.ID)
	if first.State != "published" || first.Result == nil || first.Result.Detections != 1 || first.LivePublished {
		t.Fatalf("import: %+v", first)
	}
	server := &Server{history: m}
	requestHTTP := httptest.NewRequest("GET", "/api/history/results/"+filepath.Base(first.OutputPath)+"/detections", nil)
	requestHTTP.SetPathValue("name", filepath.Base(first.OutputPath))
	response := httptest.NewRecorder()
	server.historyResultDetections(response, requestHTTP, webauth.Session{})
	if response.Code != 200 || !strings.Contains(response.Body.String(), "192.0.2.1") {
		t.Fatalf("isolated result UI API: %d %s", response.Code, response.Body.String())
	}
	comparison, err := m.rewriteRule("login")
	if err != nil {
		t.Fatal(err)
	}
	second := waitDone(comparison.ID)
	if second.State != "published" || second.Request.ParentImportID != first.Result.ImportID || second.Result == nil {
		t.Fatalf("comparison: %+v", second)
	}
	if _, err := m.publish(context.Background(), comparison.ID); err == nil {
		t.Fatal("comparison published")
	}
	if _, err := os.Stat(filepath.Join(root, "live.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("live database touched: %v", err)
	}
}
