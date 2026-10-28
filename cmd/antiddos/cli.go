package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/app"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	challengeService "github.com/it-nsk/antiddos/internal/challenge"
	"github.com/it-nsk/antiddos/internal/challengeadmin"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/control"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/storage"
	"github.com/it-nsk/antiddos/internal/webcontrol"
)

const usage = `Usage:
  antiddos run [OPTIONS]       run the analyzer directly
  antiddos monitor [OPTIONS]   show traffic, detections, and active blocks
  antiddos web [OPTIONS]       serve the local web interface
  antiddos challenge [OPTIONS] run the isolated soft-block checker
  antiddos challenge-keys rotate [OPTIONS] rotate checker signing keys
  antiddos nginx-snippet [OPTIONS] preview Nginx soft-block include files
  antiddos soft-block COMMAND manage soft-block prerequisites and rollback config
  antiddos user COMMAND        manage web users (add/list/password/delete)
  antiddos unblock IP          remove one IP from the firewall block set

The systemd service reads /etc/antiddos/config.json. Values from
/etc/default/antiddos can override its paths:
  ANTIDDOS_LOG_FILE=/var/log/nginx/access.log

Monitor continuously until Ctrl+C:
  antiddos monitor
`

func execute(ctx context.Context, args []string, logger *slog.Logger) error {
	return executeCommand(ctx, args, logger, os.Stdout)
}

func executeCommand(ctx context.Context, args []string, logger *slog.Logger, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}

	var err error
	switch args[0] {
	case "launch":
		err = launch(ctx, args[1:], logger)
	case "run":
		err = run(ctx, args, logger)
	case "monitor":
		err = monitor(ctx, args[1:], out)
	case "web":
		err = webCommand(ctx, args[1:], logger, out)
	case "challenge":
		err = challengeCommand(ctx, args[1:], logger, out)
	case "challenge-keys":
		err = challengeKeysCommand(args[1:], out, time.Now())
	case "nginx-snippet":
		err = nginxSnippetCommand(args[1:], out)
	case "soft-block":
		err = softBlockCommand(ctx, args[1:], out)
	case "user":
		err = userCommand(ctx, args[1:], out)
	case "unblock":
		err = unblock(ctx, args[1:], out)
	default:
		err = fmt.Errorf("unknown command %q; use antiddos --help", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

// launch is the systemd entry point. It retains CAP_NET_ADMIN only when an
// effective rule action uses nftables. Before dropping the capability it
// removes leases left by a previously enabled firewall configuration.
func launch(ctx context.Context, args []string, logger *slog.Logger) error {
	options, err := parseRunFlags(args, os.Stderr)
	if err != nil {
		return err
	}
	cfg, err := config.LoadWithLogFile(options.Config, options.LogFile)
	if err != nil {
		return err
	}
	if _, err := blockpolicy.New(cfg.BlockDuration); err != nil {
		return fmt.Errorf("validate block policy: %w", err)
	}
	if !config.UsesNFTables(cfg) {
		if err := app.ReconcileDisabledNFTables(ctx, cfg, &action.NFTables{BlockTCPPorts: cfg.BlockTCPPorts}, logger); err != nil {
			return err
		}
		setpriv, err := exec.LookPath("setpriv")
		if err != nil {
			return fmt.Errorf("dry-run startup requires util-linux setpriv to drop CAP_NET_ADMIN: %w", err)
		}
		binary, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate antiddos executable: %w", err)
		}
		childArgs := []string{setpriv, "--no-new-privs", "--inh-caps=-net_admin", "--ambient-caps=-net_admin", "--", binary, "run"}
		childArgs = append(childArgs, args...)
		childArgs = append(childArgs, "--control-socket", control.DefaultSocketPath)
		childArgs = append(childArgs, "--web-socket", webcontrol.DefaultSocketPath)
		return syscall.Exec(setpriv, childArgs, os.Environ())
	}
	nftables := &action.NFTables{BlockTCPPorts: cfg.BlockTCPPorts}
	if err := nftables.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize nftables blocking: %w", err)
	}
	return app.Run(ctx, app.RunOptions{
		Config: options.Config, LogFile: options.LogFile,
		ControlSocketPath: control.DefaultSocketPath,
		WebSocketPath:     webcontrol.DefaultSocketPath,
		FromStart:         options.FromStart, PrintLines: options.PrintLines, PrintEvents: options.PrintEvents,
	}, logger)
}

func unblock(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: antiddos unblock IP")
	}
	ip, err := netip.ParseAddr(args[0])
	if err != nil {
		return fmt.Errorf("invalid IP address %q: %w", args[0], err)
	}
	result, err := control.RequestUnblock(ctx, control.DefaultSocketPath, ip)
	if err != nil {
		return err
	}
	if result.Status == action.StatusFailed {
		return result.Err
	}
	_, err = fmt.Fprintf(out, "%s: %s\n", result.IP, result.Status)
	return err
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	options, err := parseRunFlags(args[1:], os.Stderr)
	if err != nil {
		return err
	}
	var softFeedGroupID *int
	if options.SoftFeedGroup != "" {
		group, err := user.LookupGroup(options.SoftFeedGroup)
		if err != nil {
			return fmt.Errorf("lookup soft feed socket group %q: %w", options.SoftFeedGroup, err)
		}
		groupID, err := strconv.Atoi(group.Gid)
		if err != nil {
			return fmt.Errorf("parse soft feed socket group GID: %w", err)
		}
		softFeedGroupID = &groupID
	}
	return app.Run(ctx, app.RunOptions{
		Config: options.Config, LogFile: options.LogFile, ControlSocketPath: options.ControlSocket, WebSocketPath: options.WebSocket,
		FromStart: options.FromStart, PrintLines: options.PrintLines, PrintEvents: options.PrintEvents,
		SoftFeedSocketPath: options.SoftFeedSocket, SoftFeedSocketGroupID: softFeedGroupID,
	}, logger)
}

func challengeCommand(ctx context.Context, args []string, logger *slog.Logger, out io.Writer) error {
	credentialPath := ""
	if directory := os.Getenv("CREDENTIALS_DIRECTORY"); directory != "" {
		credentialPath = filepath.Join(directory, challengeService.DefaultCredentialName)
	}
	feedSocket := softfeed.DefaultSocketPath
	checkSocket := challengeService.DefaultCheckSocketPath
	adminSocket := challengeService.DefaultAdminSocketPath
	metricsPath := challengeService.DefaultMetricsPath
	checkGroup := "antiddos-check"
	adminGroup := "antiddos-challenge-read"
	f := flag.NewFlagSet("challenge", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&credentialPath, "credential-file", credentialPath, "systemd LoadCredential file containing provider and cookie keys")
	f.StringVar(&feedSocket, "feed-socket", feedSocket, "daemon read-only feed Unix socket")
	f.StringVar(&checkSocket, "check-socket", checkSocket, "public Nginx check/challenge Unix socket")
	f.StringVar(&checkGroup, "check-group", checkGroup, "group allowed to connect to the public check socket")
	f.StringVar(&adminSocket, "admin-socket", adminSocket, "read-only checker status and metrics Unix socket")
	f.StringVar(&metricsPath, "metrics-db", metricsPath, "checker aggregate metrics SQLite path")
	f.StringVar(&adminGroup, "admin-group", adminGroup, "group allowed to connect to the read-only admin socket")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	group, err := user.LookupGroup(checkGroup)
	if err != nil {
		return fmt.Errorf("lookup check socket group %q: %w", checkGroup, err)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse check socket group GID: %w", err)
	}
	admin, err := user.LookupGroup(adminGroup)
	if err != nil {
		return fmt.Errorf("lookup admin socket group %q: %w", adminGroup, err)
	}
	adminGroupID, err := strconv.Atoi(admin.Gid)
	if err != nil {
		return fmt.Errorf("parse admin socket group GID: %w", err)
	}
	return challengeService.Run(ctx, challengeService.RuntimeOptions{FeedSocketPath: feedSocket, CheckSocketPath: checkSocket, AdminSocketPath: adminSocket, CredentialPath: credentialPath, MetricsPath: metricsPath, CheckSocketGroupID: groupID, AdminSocketGroupID: adminGroupID}, logger)
}

type runOptions struct {
	Config, LogFile, ControlSocket, WebSocket string
	SoftFeedSocket, SoftFeedGroup             string
	FromStart, PrintLines, PrintEvents        bool
}

func parseRunFlags(args []string, out io.Writer) (runOptions, error) {
	o := runOptions{
		Config:  configPath(),
		LogFile: os.Getenv("ANTIDDOS_LOG_FILE"),
	}
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&o.ControlSocket, "control-socket", "", "optional local control socket")
	f.StringVar(&o.WebSocket, "web-socket", "", "optional restricted web API socket")
	f.StringVar(&o.SoftFeedSocket, "soft-feed-socket", "", "override soft-block feed Unix socket (test isolation)")
	f.StringVar(&o.SoftFeedGroup, "soft-feed-group", "", "override soft-block feed socket group (test isolation)")
	f.StringVar(&o.Config, "config", o.Config, "configuration file")
	f.StringVar(&o.LogFile, "log-file", o.LogFile, "override log_file")
	f.BoolVar(&o.FromStart, "from-start", false, "read the existing log from the beginning")
	f.BoolVar(&o.PrintLines, "print-lines", false, "print input lines for debugging")
	f.BoolVar(&o.PrintEvents, "print-events", false, "print parsed events for debugging")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 {
		return o, fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return o, nil
}

type monitorOptions struct {
	Config               string
	ChallengeAdminSocket string
	Once                 bool
	Limit                int
}

func monitor(ctx context.Context, args []string, out io.Writer) error {
	o := monitorOptions{
		Config:               configPath(),
		ChallengeAdminSocket: challengeadmin.DefaultSocketPath,
	}
	f := flag.NewFlagSet("monitor", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&o.Config, "config", o.Config, "configuration file")
	f.StringVar(&o.ChallengeAdminSocket, "challenge-admin-socket", o.ChallengeAdminSocket, "read-only challenge status Unix socket")
	f.BoolVar(&o.Once, "once", false, "print one snapshot and exit")
	f.IntVar(&o.Limit, "limit", 20, "number of traffic intervals, detections, and active blocks to show (1-1000)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if o.Limit < 1 || o.Limit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}

	cfg, err := monitorConfig(o)
	if err != nil {
		return err
	}
	path := cfg.DatabasePath
	database, err := storage.OpenReader(path)
	if err != nil {
		return err
	}
	defer database.Close()

	show := func() error {
		now := time.Now()
		traffic, err := database.Traffic(ctx, o.Limit)
		if err != nil {
			return err
		}
		alerts, err := database.Detections(ctx, o.Limit)
		if err != nil {
			return err
		}
		blocks, err := database.ActiveBlocks(ctx, now, o.Limit)
		if err != nil {
			return err
		}
		if !o.Once {
			clearTerminal(out)
		}
		if len(cfg.LogSources) == 1 {
			fmt.Fprintf(out, "Log: %s\n", cfg.LogSources[0].Path)
		} else {
			fmt.Fprintln(out, "Logs:")
			for _, source := range cfg.LogSources {
				fmt.Fprintf(out, "  %s: %s\n", source.ID, source.Path)
			}
		}
		fmt.Fprintf(out, "Database: %s\nUpdated: %s\nMode: %s\n", path, now.Format(time.RFC3339), cfg.BlockMode)
		if config.UsesSoftBlock(cfg) {
			checker := &challengeadmin.Client{SocketPath: o.ChallengeAdminSocket}
			status, statusErr := checker.Status(ctx)
			if statusErr != nil {
				fmt.Fprintln(out, "Challenge: unavailable (main dashboard remains available)")
				fmt.Fprintln(out, "Checker outages: exact fail-open count is unknown.")
			} else {
				fmt.Fprintf(out, "Challenge: %s (running mode=%s revision=%s sites=%d)\n", status.Health, status.Mode, safeText(status.ConfigRevision), status.Sites)
				fmt.Fprintf(out, "Metrics: %s (dropped=%d; newest bucket may not be flushed)\n", defaultMetricHealth(status.MetricsHealth), status.MetricsDropped)
				fmt.Fprintf(out, "\nCHALLENGE METRICS (last 15 minutes, up to %d buckets)\n", o.Limit)
				rows, metricsErr := checker.Metrics(ctx, now.Add(-15*time.Minute), now, o.Limit)
				if metricsErr != nil {
					fmt.Fprintln(out, "(metrics unavailable)")
				} else if len(rows) == 0 {
					fmt.Fprintln(out, "(no flushed metrics)")
				} else {
					fmt.Fprintln(out, "BUCKET  SITE  REASON  COUNT")
					for _, row := range rows {
						fmt.Fprintf(out, "%s  %s  %s  %d\n", time.Unix(row.Bucket, 0).Format(time.RFC3339), row.Site, row.Reason, row.Count)
					}
					if len(rows) == o.Limit {
						fmt.Fprintln(out, "(result may be truncated)")
					}
				}
				fmt.Fprintln(out, "Checker outages: exact fail-open count is unknown.")
			}
		}
		fmt.Fprintf(out, "\nTRAFFIC (latest %d intervals)\n", o.Limit)
		if err := printTraffic(out, traffic); err != nil {
			return err
		}
		fmt.Fprintf(out, "\nDETECTIONS (latest %d)\n", o.Limit)
		if err := printAlerts(out, alerts); err != nil {
			return err
		}
		fmt.Fprintf(out, "\nBLOCKS (active, latest %d)\n", o.Limit)
		return printBlocks(out, blocks, now)
	}

	if err := show(); err != nil || o.Once {
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := show(); err != nil {
				return err
			}
		}
	}
}

func defaultMetricHealth(value string) string {
	if value == "" {
		return "unavailable"
	}
	return value
}

func printBlocks(out io.Writer, rows []storage.BlockRow, now time.Time) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tRULE\tBLOCKED AT\tEXPIRES AT\tREMAINING")
	for _, row := range rows {
		remaining := row.ExpiresAt.Sub(now).Round(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", row.IP, safeText(row.RuleID), row.StartedAt.Format(time.RFC3339), row.ExpiresAt.Format(time.RFC3339), remaining)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no active blocks)")
	}
	return w.Flush()
}

func monitorConfig(o monitorOptions) (config.Config, error) {
	logFile, err := monitorLogFileOverride(o.Config, os.Getenv("ANTIDDOS_LOG_FILE"), "/etc/default/antiddos")
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := config.LoadWithLogFile(o.Config, logFile)
	if err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func monitorLogFileOverride(configFile, environmentValue, environmentFile string) (string, error) {
	if environmentValue != "" {
		return environmentValue, nil
	}
	if filepath.Clean(configFile) != config.DefaultPath {
		return "", nil
	}

	contents, err := os.ReadFile(environmentFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read service environment file %q: %w", environmentFile, err)
	}
	return parseLogFileOverride(string(contents)), nil
}

func parseLogFileOverride(contents string) string {
	var value string
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, item, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ANTIDDOS_LOG_FILE" {
			continue
		}
		item = strings.TrimSpace(item)
		if len(item) >= 2 && ((item[0] == '"' && item[len(item)-1] == '"') || (item[0] == '\'' && item[len(item)-1] == '\'')) {
			item = item[1 : len(item)-1]
		}
		value = item
	}
	return value
}

func configPath() string {
	if path := os.Getenv("ANTIDDOS_CONFIG"); path != "" {
		return path
	}
	return config.DefaultPath
}

func clearTerminal(out io.Writer) {
	if file, ok := out.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(out, "\x1b[H\x1b[2J")
		}
	}
}

func printAlerts(out io.Writer, rows []storage.DetectionRow) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "EVENT TIME\tRULE\tGROUPING\tGROUP\tIP\tUSER AGENT\tCOUNT\tWINDOW\tTHRESHOLD")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\n", r.EventTimeText, safeText(r.RuleID), safeText(r.GroupingID), safeText(r.GroupValuesJSON), safeText(r.TriggerIP), safeText(r.TriggerUserAgent), r.RequestCount, time.Duration(r.WindowMillis)*time.Millisecond, r.Threshold)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no detections)")
	}
	return w.Flush()
}

func safeText(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			fmt.Fprintf(&result, "\\u%04x", r)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func printTraffic(out io.Writer, rows []metrics.Sample) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "BUCKET START\tREQUESTS\tMATCHED\tREQ/S\tBYTES\tBYTES/S\tAVG RESPONSE")
	for _, r := range rows {
		average := "-"
		if r.KnownResponseByteRows > 0 {
			average = fmt.Sprintf("%.1f", float64(r.ResponseBytes)/float64(r.KnownResponseByteRows))
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%.2f\t%d\t%.2f\t%s\n", time.Unix(r.BucketStartUnix, 0).Format(time.RFC3339), r.Requests, r.MatchedRequests, float64(r.Requests)/float64(r.IntervalSeconds), r.ResponseBytes, float64(r.ResponseBytes)/float64(r.IntervalSeconds), average)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no samples yet; statistics are written every 15 seconds)")
	}
	return w.Flush()
}
