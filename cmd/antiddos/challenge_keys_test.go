package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	challengeService "github.com/it-nsk/antiddos/internal/challenge"
)

func TestChallengeKeysRotateCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	body := `{"provider_secret":"` + encode("0123456789abcdef0123456789abcdef") + `","current":{"id":"k1","secret":"` + encode("abcdef0123456789abcdef0123456789") + `"},"previous":[]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := challengeKeysCommand([]string{"rotate", "--file", path}, &out, time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "restart antiddos-challenge.service") {
		t.Fatalf("output=%q", out.String())
	}
	_, ring, err := challengeService.LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Current.ID == "k1" || len(ring.Previous) != 1 || ring.Previous[0].ID != "k1" {
		t.Fatalf("ring=%+v", ring)
	}
}
