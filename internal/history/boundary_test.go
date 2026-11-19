package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAllowedDirectory(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "archives")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateAllowedDirectory(inside, []string{root}); err != nil {
		t.Fatalf("inside root: %v", err)
	}
	if err := validateAllowedDirectory(filepath.Dir(root), []string{root}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside root error = %v", err)
	}
}

func TestValidateAllowedDirectoryRequiresRoots(t *testing.T) {
	if err := ValidateAllowedDirectory(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("empty roots error = %v", err)
	}
}
