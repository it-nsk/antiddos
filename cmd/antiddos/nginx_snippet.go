package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/nginxsnippet"
)

func nginxSnippetCommand(args []string, out io.Writer) error {
	configFile := configPath()
	siteID := ""
	outputDir := ""
	write := false
	f := flag.NewFlagSet("nginx-snippet", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configFile, "AntiDDoS configuration file")
	f.StringVar(&siteID, "site", "", "soft-block site ID")
	f.StringVar(&outputDir, "output", "", "directory used in include instructions and optional file output")
	f.BoolVar(&write, "write", false, "write preview files without replacing existing files")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if siteID == "" {
		return errors.New("--site is required")
	}
	if outputDir == "" {
		return errors.New("--output is required")
	}
	absoluteOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !config.UsesSoftBlock(cfg) {
		return fmt.Errorf("nginx-snippet requires a mode with soft-block rules")
	}
	var site *config.SiteConfig
	for i := range cfg.SoftBlock.Sites {
		if cfg.SoftBlock.Sites[i].ID == siteID {
			site = &cfg.SoftBlock.Sites[i]
			break
		}
	}
	if site == nil {
		return fmt.Errorf("soft-block site %q is not configured", siteID)
	}
	sourceByID := make(map[string]config.LogSourceConfig, len(cfg.LogSources))
	for _, source := range cfg.LogSources {
		sourceByID[source.ID] = source
	}
	sources := make([]config.LogSourceConfig, 0, len(site.LogSources))
	for _, sourceID := range site.LogSources {
		source, ok := sourceByID[sourceID]
		if !ok {
			return fmt.Errorf("site %q references missing log source %q", siteID, sourceID)
		}
		sources = append(sources, source)
	}
	files, err := nginxsnippet.Render(*site, sources, absoluteOutput)
	if err != nil {
		return err
	}
	if write {
		if err := nginxsnippet.Write(absoluteOutput, files); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "Wrote %d preview files to %s. No active Nginx configuration was edited or reloaded.\n", len(files), absoluteOutput)
		return err
	}
	for _, file := range files {
		if _, err := fmt.Fprintf(out, "===== %s =====\n%s", filepath.Join(absoluteOutput, file.Name), file.Content); err != nil {
			return err
		}
		if !strings.HasSuffix(file.Content, "\n") {
			if _, err := io.WriteString(out, "\n"); err != nil {
				return err
			}
		}
	}
	return nil
}
