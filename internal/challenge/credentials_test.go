package challenge

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCredentialsAcceptsPrivateCredentialAndRejectsInvalidOrPublicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	body := `{"provider_secret":"` + encode("0123456789abcdef0123456789abcdef") + `","current":{"id":"k1","secret":"` + encode("abcdef0123456789abcdef0123456789") + `"},"previous":[]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	provider, ring, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(provider) != "0123456789abcdef0123456789abcdef" || ring.Current.ID != "k1" || string(ring.Current.Secret) != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("decoded credentials mismatch")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCredentials(path); err == nil {
		t.Fatal("accepted group/world-readable credentials")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"provider_secret":"bad","current":{"id":"k1","secret":"`+encode("abcdef0123456789abcdef0123456789")+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCredentials(path); err == nil {
		t.Fatal("accepted invalid provider secret")
	}
}

func TestLoadCredentialsAcceptsSystemdCredentialMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	body := `{"provider_secret":"` + encode("0123456789abcdef0123456789abcdef") + `","current":{"id":"k1","secret":"` + encode("abcdef0123456789abcdef0123456789") + `"},"previous":[]}`
	if err := os.WriteFile(path, []byte(body), 0440); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, _, err := LoadCredentials(path); err != nil {
		t.Fatalf("LoadCredentials rejected a systemd-provided 0440 credential: %v", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Join(dir, "different"))
	if _, _, err := LoadCredentials(path); err == nil {
		t.Fatal("accepted group-readable credentials outside CREDENTIALS_DIRECTORY")
	}
}
