package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const DefaultPath = "/etc/antiddos/config.json"

type Config struct {
	LogFile       string `json:"log_file"`
	StartPosition string `json:"start_position"`
}

func Load(path string) (Config, error) {
	cfg := Config{StartPosition: "end"}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("unexpected data after the JSON object")
		}
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	if cfg.LogFile == "" {
		return Config{}, fmt.Errorf("config %q: log_file is required", path)
	}
	if !filepath.IsAbs(cfg.LogFile) {
		return Config{}, fmt.Errorf("config %q: log_file must be an absolute path", path)
	}
	if cfg.StartPosition != "end" && cfg.StartPosition != "beginning" {
		return Config{}, fmt.Errorf("config %q: start_position must be %q or %q", path, "end", "beginning")
	}

	return cfg, nil
}
