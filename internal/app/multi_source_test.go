package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/storage"
)

type messageHandler struct{ messages chan string }

func (handler messageHandler) Enabled(context.Context, slog.Level) bool { return true }
func (handler messageHandler) WithAttrs([]slog.Attr) slog.Handler       { return handler }
func (handler messageHandler) WithGroup(string) slog.Handler            { return handler }
func (handler messageHandler) Handle(_ context.Context, record slog.Record) error {
	message := record.Message
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == "rule" {
			message += ":" + attribute.Value.String()
		}
		return true
	})
	handler.messages <- message
	return nil
}

func TestRunRoutesMultipleLogSourcesAndAppliesRuleWhitelist(t *testing.T) {
	directory := t.TempDir()
	webPath := filepath.Join(directory, "web.log")
	adminPath := filepath.Join(directory, "admin.log")
	databasePath := filepath.Join(directory, "state.sqlite")
	for _, path := range []string{webPath, adminPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "config.json")
	configJSON := fmt.Sprintf(`{
		"log_sources":{
			"web":{"path":%q,"format":"nginx_custom","log_format":"log_format test '$remote_addr|$time_iso8601|$request_method|$request_uri|$status|$http_user_agent';"},
			"admin":%q
		},
		"database_path":%q,
		"start_position":"end",
		"block_mode":"dry_run",
		"engine":{"ignore_ips":["192.0.2.9"],"rules":[
			{"id":"home","log_source":"web","path_regex":"^/$","window":"20s","threshold":2,"group_by":"ip","ignore_ips":["198.51.100.7"]},
			{"id":"home-alt","log_source":"web","path_regex":"^/$","window":"20s","threshold":2,"group_by":"ip"},
			{"id":"login","log_source":"admin","path_regex":"^/login$","window":"20s","threshold":2,"group_by":"ip"}
		]}
	}`, webPath, adminPath, databasePath)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	messages := make(chan string, 32)
	logger := slog.New(messageHandler{messages: messages})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, RunOptions{Config: configPath}, logger) }()
	waitMessage(t, messages, "service started")

	base := time.Now().UTC().Add(2 * time.Second)
	webLines := []string{
		customNginxLine(base, "192.0.2.9", "/"),
		customNginxLine(base.Add(time.Second), "198.51.100.7", "/"),
		customNginxLine(base.Add(2*time.Second), "203.0.113.7", "/"),
		customNginxLine(base.Add(3*time.Second), "203.0.113.7", "/"),
		customNginxLine(base.Add(4*time.Second), "203.0.113.8", "/login"), // matches only the other source's rules
	}
	adminLines := []string{
		nginxLine(base, "192.0.2.9", "/login"),
		nginxLine(base.Add(time.Second), "192.0.2.9", "/login"),
		nginxLine(base.Add(2*time.Second), "198.51.100.7", "/login"),
		nginxLine(base.Add(3*time.Second), "198.51.100.7", "/login"),
		nginxLine(base.Add(4*time.Second), "203.0.113.8", "/"), // matches only the other source's rule
	}
	appendLines(t, webPath, webLines)
	appendLines(t, adminPath, adminLines)
	seenRules := make(map[string]bool)
	deadline := time.After(5 * time.Second)
	for len(seenRules) < 3 {
		select {
		case message := <-messages:
			if strings.HasPrefix(message, "request pattern detected:") {
				seenRules[strings.TrimPrefix(message, "request pattern detected:")] = true
			}
		case <-deadline:
			cancel()
			<-done
			t.Fatal("timed out waiting for detections from both sources")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("app.Run did not stop after cancellation")
	}

	database, err := storage.OpenReader(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	detections, err := database.Detections(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	gotRules := make(map[string]bool)
	for _, detection := range detections {
		gotRules[detection.RuleID] = true
	}
	if len(detections) != 3 || !gotRules["home"] || !gotRules["home-alt"] || !gotRules["login"] {
		t.Fatalf("detections = %#v, want two detections from shared source and one from admin", detections)
	}
	traffic, err := database.Traffic(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var requests, matched int64
	for _, sample := range traffic {
		requests += sample.Requests
		matched += sample.MatchedRequests
	}
	if requests != 10 || matched != 8 {
		t.Fatalf("traffic totals = requests %d, matched %d, want 10 and 8 (source-specific matches and whitelists)", requests, matched)
	}
}

func waitMessage(t *testing.T, messages <-chan string, want string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case got := <-messages:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func appendLines(t *testing.T, path string, lines []string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func nginxLine(timestamp time.Time, ip, path string) string {
	return fmt.Sprintf(`%s - - [%s] "GET %s HTTP/1.1" 200 123 "-" "test-agent"`, ip, timestamp.Format("02/Jan/2006:15:04:05 -0700"), path)
}

func customNginxLine(timestamp time.Time, ip, path string) string {
	return fmt.Sprintf("%s|%s|GET|%s|200|test-agent", ip, timestamp.Format(time.RFC3339), path)
}
