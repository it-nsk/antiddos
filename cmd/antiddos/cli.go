package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/storage"
)

const usage = `Usage:
  antiddos run [OPTIONS]       run the analyzer (used by systemd)
  antiddos monitor [OPTIONS]   show traffic and detections from SQLite

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
	case "run":
		err = run(ctx, args, logger)
	case "monitor":
		err = monitor(ctx, args[1:], out)
	default:
		err = fmt.Errorf("unknown command %q; use antiddos --help", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

type runOptions struct {
	Config, LogFile                    string
	FromStart, PrintLines, PrintEvents bool
}

func parseRunFlags(args []string, out io.Writer) (runOptions, error) {
	o := runOptions{
		Config:  configPath(),
		LogFile: os.Getenv("ANTIDDOS_LOG_FILE"),
	}
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	f.SetOutput(out)
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
	Config string
	Once   bool
}

func monitor(ctx context.Context, args []string, out io.Writer) error {
	o := monitorOptions{
		Config: configPath(),
	}
	f := flag.NewFlagSet("monitor", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&o.Config, "config", o.Config, "configuration file")
	f.BoolVar(&o.Once, "once", false, "print one snapshot and exit")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
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
		traffic, err := database.Traffic(ctx, 20)
		if err != nil {
			return err
		}
		alerts, err := database.Detections(ctx, 20)
		if err != nil {
			return err
		}
		if !o.Once {
			clearTerminal(out)
		}
		fmt.Fprintf(out, "Log: %s\nDatabase: %s\nUpdated: %s\n\nTRAFFIC (latest 20 intervals)\n", cfg.LogFile, path, time.Now().Format(time.RFC3339))
		if err := printTraffic(out, traffic); err != nil {
			return err
		}
		fmt.Fprintln(out, "\nDETECTIONS (latest 20)")
		return printAlerts(out, alerts)
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

func monitorConfig(o monitorOptions) (config.Config, error) {
	cfg, err := config.Load(o.Config)
	if err != nil {
		return config.Config{}, err
	}
	return cfg, nil
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
