package webcontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/challengeadmin"
	"github.com/it-nsk/antiddos/internal/configservice"
	"github.com/it-nsk/antiddos/internal/storage"
)

func TestChallengeMetricsProxy(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "checker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/status" {
			_, _ = w.Write([]byte(`{"health":"ready","sites":1,"metrics_health":"ready","metrics_dropped":0}`))
			return
		}
		_, _ = w.Write([]byte(`[{"bucket":1,"site":"main","reason":"issued","count":3}]`))
	})}
	go server.Serve(l)
	defer server.Close()
	s := &Service{Challenge: &challengeadmin.Client{SocketPath: socket}}
	now := time.Now().UTC().Truncate(time.Second)
	path := fmt.Sprintf("/v1/challenge/metrics?from=%d&to=%d&limit=10", now.Add(-time.Hour).Unix(), now.Unix())
	response := httptest.NewRecorder()
	s.handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"count":3`) {
		t.Fatalf("response %d: %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	s.handler().ServeHTTP(response, httptest.NewRequest("GET", "/v1/challenge/metrics?from=0&to=9999999&limit=1001", nil))
	if response.Code != 400 {
		t.Fatalf("invalid range status=%d", response.Code)
	}
	server.Close()
	response = httptest.NewRecorder()
	s.handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
	if response.Code != 503 {
		t.Fatalf("unavailable status=%d", response.Code)
	}
}

func TestDaemonWebAPIOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	databasePath := filepath.Join(dir, "stats.sqlite")
	configJSON := `{
  "log_sources": {"main":"/tmp/access.log","admin":"/tmp/admin.log"},
  "database_path":"` + databasePath + `",
  "block_mode":"dry_run",
  "block_duration":"1m",
  "engine":{"ignore_ips":[],"rules":[
    {"id":"home","log_source":"main","path_regex":"^/$","window":"5s","threshold":5,"group_by":"ip","ignore_ips":[]},
    {"id":"login","log_source":"admin","path_regex":"^/login$","window":"5s","threshold":3,"group_by":"ip","ignore_ips":["198.51.100.7"]}
  ]}
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := storage.OpenReader(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	config := &configservice.Service{Path: configPath}
	loaded, err := config.Read()
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		Config: config,
		Stats:  reader,
		Status: Status{ConfigRevision: loaded.Revision, StartedAt: time.Now(), BlockMode: "dry_run"},
	}
	socket := filepath.Join(dir, "web.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, socket, service) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stop daemon web API: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("daemon web API did not stop")
		}
	})

	client := NewClient(socket)
	var state ConfigState
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state, err = client.Config(context.Background())
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0660 {
		t.Fatalf("socket mode: %v, %v", info, err)
	}
	if len(state.Config.Sources) != 2 || len(state.Config.Rules) != 2 || state.RestartRequired == nil || *state.RestartRequired {
		t.Fatalf("initial state: %+v", state)
	}

	globalIPs := []string{"192.0.2.0/24"}
	homeIPs := []string{"2001:db8::/32"}
	loginIPs := []string{"198.51.100.7"}
	homeRegex := "^/start$"
	update := configservice.Update{
		Revision:  state.Config.Revision,
		IgnoreIPs: &globalIPs,
		Rules: map[string]configservice.RuleUpdate{
			"home":  {IgnoreIPs: &homeIPs, PathRegex: &homeRegex},
			"login": {IgnoreIPs: &loginIPs},
		},
	}
	changed, err := client.SaveRules(context.Background(), update)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RestartRequired == nil || !*changed.RestartRequired || len(changed.Config.Rules[0].IgnoreIPs) != 1 || changed.Config.Rules[0].PathRegex != homeRegex {
		t.Fatalf("updated state: %+v", changed)
	}
	if _, err := client.SaveRules(context.Background(), update); err == nil {
		t.Fatal("stale update was accepted")
	} else {
		var remote *RemoteError
		if !errors.As(err, &remote) || remote.Status != 409 {
			t.Fatalf("stale update error: %v", err)
		}
	}

	now := time.Now()
	dashboard, err := client.Dashboard(context.Background(), now.Add(-time.Hour), now, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard.Points) == 0 || len(dashboard.Points) > 600 || dashboard.Detections == nil || dashboard.Blocks == nil {
		t.Fatalf("dashboard bounds: %+v", dashboard)
	}
	decisions, err := client.SoftBlocks(context.Background(), 10)
	if err != nil || decisions == nil || len(decisions) != 0 {
		t.Fatalf("soft blocks=%+v error=%v", decisions, err)
	}
	if _, err := client.SoftBlocks(context.Background(), 1001); err == nil {
		t.Fatal("unbounded soft-block query accepted")
	}
	var output any
	if err := client.request(context.Background(), "PUT", "/v1/config/rules", map[string]any{"revision": changed.Config.Revision, "unknown": true}, &output); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
}
