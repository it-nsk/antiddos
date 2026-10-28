package challenge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
)

func TestAdminStatusIsReadOnlyAndAbsentFromPublicMux(t *testing.T) {
	now := time.Now().UTC()
	state := softfeed.NewState()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: "status-epoch", Revision: 7, Mode: "soft_block", ConfigRevision: "cfg7", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "bgt", Hosts: []string{"bgt.my"}}}, Decisions: []softfeed.Decision{}}
	raw, _ := json.Marshal(snapshot)
	if err := state.ApplyJSON(raw, now); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(state, Options{ProviderSecret: []byte("0123456789abcdef0123456789abcdef"), CookieKeys: Keyring{Current: Key{ID: "k1", Secret: []byte("abcdef0123456789abcdef0123456789")}}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	public := httptest.NewRecorder()
	service.PublicHandler().ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if public.Code != http.StatusNotFound {
		t.Fatalf("public status code=%d", public.Code)
	}
	admin := httptest.NewRecorder()
	service.AdminHandler().ServeHTTP(admin, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if admin.Code != http.StatusOK || admin.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin status code=%d headers=%v", admin.Code, admin.Header())
	}
	var status map[string]any
	if err := json.Unmarshal(admin.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["health"] != "ready" || status["mode"] != "soft_block" || status["config_revision"] != "cfg7" || status["epoch"] != "status-epoch" || status["revision"] != float64(7) {
		t.Fatalf("status=%v", status)
	}
	if _, exists := status["decisions"]; exists {
		t.Fatal("status endpoint exposed decision data")
	}
}
