package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
)

type fakeUnblocker struct{ got netip.Addr }

func (fake *fakeUnblocker) Unblock(_ context.Context, ip netip.Addr) action.Result {
	fake.got = ip
	return action.Result{Status: action.StatusRemoved, IP: ip}
}

func TestServeAndRequestUnblockOverUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	fake := &fakeUnblocker{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, fake) }()
	deadline := time.Now().Add(2 * time.Second)
	var result action.Result
	var requestErr error
	for time.Now().Before(deadline) {
		result, requestErr = RequestUnblock(context.Background(), path, netip.MustParseAddr("2001:db8::10"))
		if requestErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if requestErr != nil {
		t.Fatalf("request through Unix socket: %v", requestErr)
	}
	if result.Status != action.StatusRemoved || fake.got != netip.MustParseAddr("2001:db8::10") {
		t.Fatalf("result=%+v manager IP=%s", result, fake.got)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control server did not stop")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("control socket remains after shutdown: %v", err)
	}
}

func TestUnblockHandlerNormalizesMappedIPv4(t *testing.T) {
	fake := &fakeUnblocker{}
	request := httptest.NewRequest(http.MethodPost, "/v1/unblock", bytes.NewBufferString(`{"ip":"::ffff:192.0.2.10"}`))
	response := httptest.NewRecorder()
	handler(fake).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body)
	}
	var result unblockResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("192.0.2.10")
	if result.Status != string(action.StatusRemoved) || result.IP != want.String() || fake.got != want {
		t.Fatalf("result=%+v got=%s", result, fake.got)
	}
}

func TestUnblockHandlerRejectsCIDRAndUnknownFields(t *testing.T) {
	for _, body := range []string{`{"ip":"192.0.2.0/24"}`, `{"ip":"192.0.2.1","extra":true}`} {
		fake := &fakeUnblocker{}
		response := httptest.NewRecorder()
		handler(fake).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/unblock", bytes.NewBufferString(body)))
		if response.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, response.Code)
		}
		if fake.got.IsValid() {
			t.Errorf("invalid body reached manager: %s", fake.got)
		}
	}
}

func TestListenRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(path); err == nil {
		t.Fatal("regular file was accepted as socket")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "keep" {
		t.Fatalf("file content changed to %q", content)
	}
}

func TestRequestUnblockRejectsInvalidAddress(t *testing.T) {
	if _, err := RequestUnblock(context.Background(), "/unused", netip.Addr{}); err == nil {
		t.Fatal("invalid IP was accepted")
	}
}
