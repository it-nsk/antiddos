package challenge

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotateCredentialsKeepsProviderAndGraceOrRevokesCookies(t *testing.T) {
	now := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "keys.json")
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	body := `{"provider_secret":"` + encode("0123456789abcdef0123456789abcdef") + `","current":{"id":"k1","secret":"` + encode("abcdef0123456789abcdef0123456789") + `"},"previous":[]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	provider, before, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	oldCookie, err := IssuePassCookie(before, "bgt", "bgt.my", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := RotateCredentials(path, false, now); err != nil {
		t.Fatal(err)
	}
	afterProvider, after, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterProvider) != string(provider) || after.Current.ID == before.Current.ID || len(after.Previous) != 1 {
		t.Fatalf("rotation result provider=%t current=%q previous=%d", string(afterProvider) == string(provider), after.Current.ID, len(after.Previous))
	}
	if got := after.Previous[0].AcceptUntil; !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("grace expiry=%s", got)
	}
	if err := VerifyPassCookie(after, oldCookie, "bgt", "bgt.my", 30*time.Minute, now.Add(time.Minute)); err != nil {
		t.Fatalf("old cookie rejected during grace: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode info=%v err=%v", info, err)
	}

	if err := RotateCredentials(path, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, revoked, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked.Previous) != 0 {
		t.Fatalf("revoke retained %d previous keys", len(revoked.Previous))
	}
	if err := VerifyPassCookie(revoked, oldCookie, "bgt", "bgt.my", 30*time.Minute, now.Add(3*time.Minute)); err == nil {
		t.Fatal("revoked cookie remained valid")
	}
}
