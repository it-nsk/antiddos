package nginxsnippet

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write stores a generated bundle without replacing any pre-existing file.
func Write(outputDir string, files []File) error {
	if !filepath.IsAbs(outputDir) {
		return fmt.Errorf("output directory must be absolute")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output path must be a real directory, not a symlink")
	}
	for _, file := range files {
		if file.Name == "" || filepath.Base(file.Name) != file.Name {
			return fmt.Errorf("invalid generated file name %q", file.Name)
		}
		path := filepath.Join(outputDir, file.Name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %q", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect output file %q: %w", path, err)
		}
	}

	created := make([]string, 0, len(files))
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for _, file := range files {
		path := filepath.Join(outputDir, file.Name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			cleanup()
			return fmt.Errorf("create output file %q: %w", path, err)
		}
		created = append(created, path)
		if _, err := f.WriteString(file.Content); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("write output file %q: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("sync output file %q: %w", path, err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return fmt.Errorf("close output file %q: %w", path, err)
		}
	}
	return nil
}
