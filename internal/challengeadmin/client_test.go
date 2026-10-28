package challengeadmin

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientReadsBoundedStatusOverUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"health":"ready","mode":"soft_block","config_revision":"cfg1","epoch":"e1","revision":3,"sites":1,"metrics_health":"degraded","metrics_dropped":4}`))
	})}
	go server.Serve(listener)
	defer func() {
		_ = server.Close()
		_ = os.Remove(path)
	}()
	status, err := (&Client{SocketPath: path, Timeout: time.Second}).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Health != "ready" || status.Mode != "soft_block" || status.Revision != 3 || status.Sites != 1 || status.MetricsHealth != "degraded" || status.MetricsDropped != 4 {
		t.Fatalf("status=%+v", status)
	}
}

func TestClientReadsMetricsAndEnforcesBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metrics" || r.URL.Query().Get("limit") != "10" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`[{"bucket":1792756800,"site":"bgt","reason":"issued","count":2}]`))
	})}
	go server.Serve(listener)
	defer server.Close()
	client := &Client{SocketPath: path}
	now := time.Now().UTC()
	rows, err := client.Metrics(context.Background(), now.Add(-time.Hour), now, 10)
	if err != nil || len(rows) != 1 || rows[0].Count != 2 || rows[0].Site != "bgt" {
		t.Fatalf("metrics=%+v error=%v", rows, err)
	}
	if _, err := client.Metrics(context.Background(), now.Add(-8*24*time.Hour), now, 10); err == nil {
		t.Fatal("accepted range over seven days")
	}
	if _, err := client.Metrics(context.Background(), now.Add(-time.Hour), now, 1001); err == nil {
		t.Fatal("accepted limit over 1000")
	}
}
