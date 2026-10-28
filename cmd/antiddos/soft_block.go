package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/challenge"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/storage"
)

func softBlockCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: antiddos soft-block doctor|prepare-v0.4-rollback|migrate-from-nftables [OPTIONS]")
	}
	switch args[0] {
	case "doctor":
		return softBlockDoctor(ctx, args[1:], out)
	case "prepare-v0.4-rollback":
		return prepareV04Rollback(args[1:], out)
	case "migrate-from-nftables":
		return migrateFromNFTables(ctx, args[1:], out)
	default:
		return errors.New("usage: antiddos soft-block doctor|prepare-v0.4-rollback|migrate-from-nftables [OPTIONS]")
	}
}

func migrateFromNFTables(ctx context.Context, args []string, out io.Writer) error {
	configFile, nftBinary := configPath(), "nft"
	confirmedStopped := false
	f := flag.NewFlagSet("soft-block migrate-from-nftables", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configFile, "AntiDDoS configuration already changed to soft_block")
	f.StringVar(&nftBinary, "nft-binary", nftBinary, "nft executable")
	f.BoolVar(&confirmedStopped, "confirm-daemon-stopped", false, "confirm the AntiDDoS daemon is stopped for offline migration")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if !confirmedStopped {
		return errors.New("--confirm-daemon-stopped is required; stop antiddos before firewall migration")
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load migration config: %w", err)
	}
	if cfg.BlockMode != config.BlockModeSoftBlock {
		return fmt.Errorf("config block_mode is %q, expected %q before migration", cfg.BlockMode, config.BlockModeSoftBlock)
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open migration database: %w", err)
	}
	defer store.Close()
	state, err := store.NFTMigrationState(ctx)
	if err != nil {
		return err
	}
	if state != "" && state != "firewall_pending" && state != "complete" {
		return fmt.Errorf("unknown nftables migration state %q", state)
	}
	nft := &action.NFTables{Binary: nftBinary}
	if state == "" {
		present, err := nft.ValidateOwnedTable(ctx)
		if err != nil {
			return fmt.Errorf("validate owned firewall before migration: %w", err)
		}
		if !present {
			return errors.New("AntiDDoS nftables table is absent and no prior validated migration is recorded")
		}
		if err := store.MarkNFTMigrationPending(ctx); err != nil {
			return err
		}
	}
	removedTable, err := nft.RemoveOwnedTable(ctx)
	if err != nil {
		return fmt.Errorf("remove owned firewall during migration: %w", err)
	}
	removedRecords, err := store.CompleteNFTMigration(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "nftables migration complete: owned_table_removed=%t active_block_records_cancelled=%d\n", removedTable, removedRecords)
	return err
}

func softBlockDoctor(ctx context.Context, args []string, out io.Writer) error {
	configFile, siteID := configPath(), ""
	feedSocket, checkSocket, nginxBinary, nginxConfig := softfeed.DefaultSocketPath, challenge.DefaultCheckSocketPath, "nginx", ""
	f := flag.NewFlagSet("soft-block doctor", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configFile, "AntiDDoS configuration file")
	f.StringVar(&siteID, "site", "", "configured soft-block site ID")
	f.StringVar(&feedSocket, "feed-socket", feedSocket, "daemon decision feed Unix socket")
	f.StringVar(&checkSocket, "check-socket", checkSocket, "challenge/check Unix socket")
	f.StringVar(&nginxBinary, "nginx-binary", nginxBinary, "Nginx executable used for version/module inspection")
	f.StringVar(&nginxConfig, "nginx-config", "", "optional Nginx config file to scan for obvious location conflicts")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if siteID == "" {
		return errors.New("--site is required")
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !config.UsesSoftBlock(cfg) {
		return fmt.Errorf("config block_mode %q has no soft-block rules", cfg.BlockMode)
	}
	foundSite := false
	for _, site := range cfg.SoftBlock.Sites {
		if site.ID == siteID {
			foundSite = true
			break
		}
	}
	if !foundSite {
		return fmt.Errorf("soft-block site %q is not configured", siteID)
	}
	if _, err := fmt.Fprintf(out, "config: OK (%s)\n", cfg.BlockMode); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "site %s: OK\n", siteID); err != nil {
		return err
	}
	printSocketStatus(out, "feed socket", feedSocket)
	printSocketStatus(out, "check socket", checkSocket)
	printNginxStatus(ctx, out, nginxBinary)
	if nginxConfig != "" {
		return scanNginxConfig(out, nginxConfig)
	}
	return nil
}

func prepareV04Rollback(args []string, out io.Writer) error {
	configFile, outputFile := configPath(), ""
	f := flag.NewFlagSet("soft-block prepare-v0.4-rollback", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configFile, "current AntiDDoS configuration file")
	f.StringVar(&outputFile, "output", outputFile, "new rollback configuration file (preview when omitted)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if _, err := config.Load(configFile); err != nil {
		return fmt.Errorf("validate current config: %w", err)
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	delete(raw, "soft_block")
	if mode, _ := raw["block_mode"].(string); mode == config.BlockModeSoftBlock || mode == config.BlockModeHybrid {
		raw["block_mode"] = config.BlockModeDryRun
	}
	if engine, ok := raw["engine"].(map[string]any); ok {
		if rules, ok := engine["rules"].([]any); ok {
			for _, item := range rules {
				if rule, ok := item.(map[string]any); ok {
					delete(rule, "action")
				}
			}
		}
	}
	prepared, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rollback config: %w", err)
	}
	prepared = append(prepared, '\n')
	if outputFile == "" {
		_, err = out.Write(prepared)
		return err
	}
	inputAbs, err := filepath.Abs(configFile)
	if err != nil {
		return err
	}
	outputAbs, err := filepath.Abs(outputFile)
	if err != nil {
		return err
	}
	if inputAbs == outputAbs {
		return errors.New("--output must differ from --config so the current config remains available")
	}
	file, err := os.OpenFile(outputAbs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create rollback config %q: %w", outputAbs, err)
	}
	if _, err := file.Write(prepared); err != nil {
		file.Close()
		return fmt.Errorf("write rollback config %q: %w", outputAbs, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close rollback config %q: %w", outputAbs, err)
	}
	_, err = fmt.Fprintf(out, "rollback config written to %s; the source config was not changed\n", outputAbs)
	return err
}

func printSocketStatus(out io.Writer, label, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		state := "MISSING"
		if !os.IsNotExist(err) {
			state = "ERROR"
		}
		_, _ = fmt.Fprintf(out, "%s: %s (%s)\n", label, state, path)
		return
	}
	if info.Mode()&os.ModeSocket == 0 {
		_, _ = fmt.Fprintf(out, "%s: ERROR (path exists but is not a Unix socket: %s)\n", label, path)
		return
	}
	_, _ = fmt.Fprintf(out, "%s: OK (mode %04o, %s)\n", label, info.Mode().Perm(), path)
}

func printNginxStatus(ctx context.Context, out io.Writer, binary string) {
	command := exec.CommandContext(ctx, binary, "-V")
	data, err := command.CombinedOutput()
	if err != nil {
		_, _ = fmt.Fprintf(out, "nginx auth_request: UNKNOWN (%s -V unavailable)\n", binary)
		return
	}
	if !strings.Contains(string(data), "--without-http_auth_request_module") {
		_, _ = fmt.Fprintln(out, "nginx auth_request: AVAILABLE (module not disabled in build flags)")
		return
	}
	_, _ = fmt.Fprintln(out, "nginx auth_request: MISSING (binary built without http_auth_request_module)")
}

func scanNginxConfig(out io.Writer, path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return fmt.Errorf("read Nginx config %q: %w", absolute, err)
	}
	content := string(data)
	conflicts := []string{}
	for _, directive := range []string{"auth_request", "satisfy any", "error_page 403"} {
		if strings.Contains(content, directive) {
			conflicts = append(conflicts, directive)
		}
	}
	if len(conflicts) == 0 {
		_, err = fmt.Fprintf(out, "nginx config scan: no obvious conflicts in %s (not a full parser)\n", absolute)
		return err
	}
	_, err = fmt.Fprintf(out, "nginx config scan: REVIEW required in %s; found %s (text scan only)\n", absolute, strings.Join(conflicts, ", "))
	return err
}
