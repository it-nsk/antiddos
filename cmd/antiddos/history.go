package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/history"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/storage"
)

const historyUsage = `Usage:
  antiddos history run [--source ID] --directory DIR --name-regex RE [OPTIONS]
  antiddos history preview --directory DIR --name-regex RE [OPTIONS]
  antiddos history import --config FILE --source ID --directory DIR \
      --name-regex RE --output FILE [OPTIONS]
  antiddos history report --database FILE
  antiddos history detections --database FILE [--limit N] [--before ID] [--from RFC3339 --to RFC3339]
  antiddos history publish --config FILE --database FILE --confirm-import ID
  antiddos history preflight --database FILE --database FILE [--database FILE...]
  antiddos history catalog list --catalog FILE
  antiddos history catalog coverage --catalog FILE --source ID --from RFC3339 --to RFC3339
  antiddos history catalog traffic --catalog FILE --from RFC3339 --to RFC3339
  antiddos history catalog detections --catalog FILE --from RFC3339 --to RFC3339 [--limit N]
  antiddos history catalog --catalog FILE --database FILE [--replace-import ID]

The RE2 regular expression is matched against each base filename in DIR, not
against the full path. Matching is not implicitly anchored; use ^ and $ when a
whole-name match is required. Preview is read-only and never opens the live
database or invokes blocking actions.

Run snapshots the source parser and enabled rules from the normal config,
analyzes all matching archives in event-time order, and atomically appends the
backdated traffic and dry-run detections to the configured database. It never
invokes blocking, soft-block, or notification actions.
`

func historyCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, historyUsage)
		return err
	}
	if args[0] == "import" {
		return historyImportCommand(ctx, args[1:], out)
	}
	if args[0] == "run" {
		return historyRunCommand(ctx, args[1:], out)
	}
	if args[0] == "report" {
		return historyReportCommand(ctx, args[1:], out)
	}
	if args[0] == "detections" {
		return historyDetectionsCommand(ctx, args[1:], out)
	}
	if args[0] == "publish" {
		return historyPublishCommand(ctx, args[1:], out)
	}
	if args[0] == "preflight" {
		return historyPreflightCommand(ctx, args[1:], out)
	}
	if args[0] == "catalog" {
		return historyCatalogCommand(ctx, args[1:], out)
	}
	if args[0] != "preview" {
		return fmt.Errorf("unknown history command %q; use antiddos history --help", args[0])
	}
	return historyPreviewCommand(ctx, args[1:], out)
}

func historyRunCommand(ctx context.Context, args []string, out io.Writer) error {
	var configFile, sourceID, directory, nameRegex, resultPath, order, timezone, workDirectory, fromText, toText string
	var syslogYear, maxFiles, maxLineBytes int
	var maxInputBytes, maxExpandedBytes, sortMemoryBytes, maxSortBytes, allowMalformed int64
	f := flag.NewFlagSet("history run", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configPath(), "normal AntiDDoS configuration")
	f.StringVar(&sourceID, "source", "", "configured logical log source (optional when only one exists)")
	f.StringVar(&directory, "directory", "", "absolute directory containing archived logs")
	f.StringVar(&nameRegex, "name-regex", "", "Go RE2 expression matched against base filenames")
	f.StringVar(&resultPath, "result", "", "retain the isolated result at this new absolute path")
	f.StringVar(&workDirectory, "work-directory", "", "existing durable directory for sort files (defaults beside the configured database)")
	f.StringVar(&order, "order", history.OrderNatural, "discovery order: natural, lexical, or first-event")
	f.StringVar(&timezone, "timezone", "", "IANA timezone for records without an offset")
	f.IntVar(&syslogYear, "syslog-year", 0, "explicit year for legacy syslog records")
	f.IntVar(&maxFiles, "max-files", 1000, "maximum matched files")
	f.Int64Var(&maxInputBytes, "max-input-bytes", 100<<30, "maximum total compressed/input bytes")
	f.Int64Var(&maxExpandedBytes, "max-expanded-bytes", 200<<30, "maximum total expanded bytes")
	f.IntVar(&maxLineBytes, "max-line-bytes", 1<<20, "maximum bytes in one log line")
	f.Int64Var(&sortMemoryBytes, "sort-memory-bytes", 256<<20, "approximate in-memory external-sort chunk size")
	f.Int64Var(&maxSortBytes, "max-sort-bytes", 50<<30, "maximum temporary external-sort disk usage")
	f.Int64Var(&allowMalformed, "allow-malformed", 0, "explicit maximum malformed lines which may be skipped")
	f.StringVar(&fromText, "from", "", "optional period start, inclusive (RFC3339; requires --to)")
	f.StringVar(&toText, "to", "", "optional period end, exclusive (RFC3339; requires --from)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	from, to, err := parseHistoryPeriod(fromText, toText)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	if sourceID == "" {
		if len(cfg.LogSources) != 1 {
			return fmt.Errorf("--source is required when the config has %d log sources", len(cfg.LogSources))
		}
		sourceID = cfg.LogSources[0].ID
	}
	if workDirectory == "" {
		workDirectory = filepath.Dir(cfg.DatabasePath)
	}
	if !filepath.IsAbs(workDirectory) {
		return fmt.Errorf("work directory must be absolute")
	}
	keepResult := resultPath != ""
	if resultPath == "" {
		resultPath, err = reserveHistoryResultPath(workDirectory)
		if err != nil {
			return err
		}
	}
	var location *time.Location
	if timezone != "" {
		location, err = time.LoadLocation(timezone)
		if err != nil {
			return fmt.Errorf("load timezone %q: %w", timezone, err)
		}
	}
	ruleIDs := make([]string, 0)
	for _, rule := range cfg.Engine.Rules {
		if rule.LogSource == sourceID && !rule.ExplicitlyDisabled {
			ruleIDs = append(ruleIDs, rule.ID)
		}
	}
	sort.Strings(ruleIDs)
	fmt.Fprintf(out, "Historical analysis: source=%s files=%s/%s rules=%s target=%s\n", sourceID, directory, nameRegex, strings.Join(ruleIDs, ","), cfg.DatabasePath)
	fmt.Fprintln(out, "Enforcement is disabled: no blocks, soft-block decisions, or notifications will be created.")
	result, err := history.Import(ctx, history.ImportOptions{
		Config: cfg, SourceID: sourceID, Directory: directory, NameRegex: nameRegex, OutputPath: resultPath,
		Order: order, Location: location, SyslogYear: syslogYear, MaxFiles: maxFiles,
		MaxInputBytes: maxInputBytes, MaxExpandedBytes: maxExpandedBytes, MaxLineBytes: maxLineBytes,
		SortMemoryBytes: sortMemoryBytes, MaxSortBytes: maxSortBytes, TempDirectory: workDirectory, AllowMalformed: allowMalformed,
		From: from, To: to,
		Progress: func(progress history.ImportProgress) {
			if progress.Stage == "read-sort" {
				fmt.Fprintf(out, "Read/sorted files: %d; lines: %d; parsed: %d\n", progress.Files, progress.Lines, progress.Parsed)
			} else {
				fmt.Fprintf(out, "Analyzed: %d/%d events; detections: %d\n", progress.Processed, progress.Parsed, progress.Detections)
			}
		},
	})
	if err != nil {
		return err
	}
	published, err := history.PublishToDatabase(ctx, result.OutputPath, cfg.DatabasePath, result.ImportID)
	if err != nil {
		fmt.Fprintf(out, "Isolated result retained for review/retry: %s (import %s)\n", result.OutputPath, result.ImportID)
		return fmt.Errorf("publish historical analysis: %w", err)
	}
	if !keepResult {
		removeHistoryResultFiles(result.OutputPath)
	}
	if published.AlreadyPublished {
		fmt.Fprintf(out, "Historical analysis was already recorded: import=%s source=%s period=[%s, %s); no rows were duplicated.\n",
			result.ImportID, sourceID, formatHistoryTime(published.Entry.From), formatHistoryTime(published.Entry.To))
	} else {
		fmt.Fprintf(out, "Historical analysis recorded: import=%s source=%s events=%d detections=%d period=[%s, %s) warm-up-complete=%t\n",
			result.ImportID, sourceID, result.Published, published.Detections, formatHistoryTime(published.Entry.From), formatHistoryTime(published.Entry.To), result.WarmupComplete)
	}
	if !result.WarmupComplete {
		fmt.Fprintln(out, "Warning: no earlier archive events were available to warm the first rule window; detections near the beginning may be undercounted.")
	}
	if keepResult {
		fmt.Fprintf(out, "Isolated result retained: %s\n", result.OutputPath)
	}
	return nil
}

func reserveHistoryResultPath(directory string) (string, error) {
	file, err := os.CreateTemp(directory, ".antiddos-history-result-*.sqlite")
	if err != nil {
		return "", fmt.Errorf("reserve history result path: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("prepare history result path: %w", err)
	}
	return path, nil
}

func removeHistoryResultFiles(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}

func historyDetectionsCommand(ctx context.Context, args []string, out io.Writer) error {
	var database, fromText, toText string
	var limit int
	var before int64
	flags := flag.NewFlagSet("history detections", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&database, "database", "", "isolated historical SQLite result")
	flags.StringVar(&fromText, "from", "", "optional inclusive RFC3339 time")
	flags.StringVar(&toText, "to", "", "optional exclusive RFC3339 time")
	flags.IntVar(&limit, "limit", 100, "rows per page (1-1000)")
	flags.Int64Var(&before, "before", 0, "pagination cursor from prior page")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if database == "" || flags.NArg() != 0 || limit < 1 || limit > 1000 || before < 0 {
		return fmt.Errorf("usage: antiddos history detections --database FILE [--limit 1..1000] [--before ID] [--from RFC3339 --to RFC3339]")
	}
	reader, err := storage.OpenReader(database)
	if err != nil {
		return err
	}
	defer reader.Close()
	imports, err := reader.HistoryImports(ctx)
	if err != nil {
		return err
	}
	if len(imports) != 1 {
		return fmt.Errorf("isolated result must contain exactly one import")
	}
	from, to := imports[0].FirstEvent, imports[0].LastEvent.Add(time.Nanosecond)
	if fromText != "" || toText != "" {
		if fromText == "" || toText == "" {
			return fmt.Errorf("from and to must be supplied together")
		}
		from, err = time.Parse(time.RFC3339, fromText)
		if err != nil {
			return err
		}
		to, err = time.Parse(time.RFC3339, toText)
		if err != nil {
			return err
		}
	}
	if !from.Before(to) {
		return fmt.Errorf("from must be before to")
	}
	fromUnix := from.Unix() / 15 * 15
	toUnix := (to.Unix() + 14) / 15 * 15
	if to.UnixNano()%int64(time.Second) != 0 && to.Unix()%15 == 0 {
		toUnix += 15
	}
	if toUnix <= fromUnix {
		toUnix = fromUnix + 15
	}
	dashboard, err := reader.Dashboard(ctx, time.Unix(fromUnix, 0), time.Unix(toUnix, 0), before, limit)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tIP\tRULE\tCOUNT/THRESHOLD\tMETHOD\tPATH\tSTATUS\tUSER AGENT")
	for _, d := range dashboard.Detections {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%s\t%s\t%d\t%s\n", d.EventTime, d.IP, d.Rule, d.Count, d.Threshold, d.Method, d.Path, d.Status, d.UserAgent)
	}
	fmt.Fprintf(w, "Total: %d; shown: %d; next --before: %d\n", dashboard.DetectionCount, len(dashboard.Detections), dashboard.NextBefore)
	return w.Flush()
}

func historyPublishCommand(ctx context.Context, args []string, out io.Writer) error {
	var configPath, resultPath, confirmImport string
	flags := flag.NewFlagSet("history publish", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&configPath, "config", config.DefaultPath, "configured target database")
	flags.StringVar(&resultPath, "database", "", "completed isolated historical result SQLite path")
	flags.StringVar(&confirmImport, "confirm-import", "", "exact immutable import ID to publish")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || resultPath == "" || confirmImport == "" {
		return fmt.Errorf("usage: antiddos history publish --config FILE --database FILE --confirm-import ID")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	result, err := history.PublishToDatabase(ctx, resultPath, cfg.DatabasePath, confirmImport)
	if err != nil {
		return err
	}
	if result.AlreadyPublished {
		_, err = fmt.Fprintf(out, "Already published: import=%s\n", result.Entry.ImportID)
		return err
	}
	_, err = fmt.Fprintf(out, "Published historical result: import=%s source=%s period=[%s, %s) traffic samples=%d detections=%d; no actions, blocks, or soft-block decisions were created.\n", result.Entry.ImportID, result.Entry.SourceID, formatHistoryTime(result.Entry.From), formatHistoryTime(result.Entry.To), result.TrafficSamples, result.Detections)
	return err
}

func historyCatalogCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "list" {
		return historyCatalogListCommand(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "traffic" {
		return historyCatalogTrafficCommand(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "detections" {
		return historyCatalogDetectionsCommand(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "coverage" {
		return historyCatalogCoverageCommand(ctx, args[1:], out)
	}
	var catalog, database, replaceImport string
	flags := flag.NewFlagSet("history catalog", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&catalog, "catalog", "", "separate historical coverage catalog SQLite path")
	flags.StringVar(&database, "database", "", "isolated historical result SQLite path")
	flags.StringVar(&replaceImport, "replace-import", "", "explicit catalog import ID to atomically replace")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || catalog == "" || database == "" {
		return fmt.Errorf("usage: antiddos history catalog --catalog FILE --database FILE")
	}
	var result history.CatalogResult
	var err error
	if replaceImport != "" {
		result, err = history.ReplaceCatalog(ctx, catalog, database, replaceImport)
	} else {
		result, err = history.PublishToCatalog(ctx, catalog, database)
	}
	if err != nil {
		return err
	}
	if result.AlreadyPublished {
		_, err = fmt.Fprintf(out, "Already cataloged: import=%s period=[%s, %s)\n", result.Entry.ImportID, formatHistoryTime(result.Entry.From), formatHistoryTime(result.Entry.To))
		return err
	}
	verb := "Cataloged isolated coverage"
	if replaceImport != "" {
		verb = "Replaced catalog ownership"
	}
	_, err = fmt.Fprintf(out, "%s: import=%s source=%s period=[%s, %s)\n", verb, result.Entry.ImportID, result.Entry.SourceID, formatHistoryTime(result.Entry.From), formatHistoryTime(result.Entry.To))
	return err
}

func historyCatalogCoverageCommand(ctx context.Context, args []string, out io.Writer) error {
	var catalog, sourceID, fromText, toText string
	flags := flag.NewFlagSet("history catalog coverage", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&catalog, "catalog", "", "historical coverage catalog SQLite path")
	flags.StringVar(&sourceID, "source", "", "logical log source ID")
	flags.StringVar(&fromText, "from", "", "inclusive RFC3339 bound")
	flags.StringVar(&toText, "to", "", "exclusive RFC3339 bound")
	if err := flags.Parse(args); err != nil {
		return err
	}
	from, to, err := parseHistoryPeriod(fromText, toText)
	if err != nil {
		return err
	}
	if flags.NArg() != 0 || catalog == "" || sourceID == "" {
		return fmt.Errorf("usage: antiddos history catalog coverage --catalog FILE --source ID --from RFC3339 --to RFC3339")
	}
	coverage, err := history.ReadCatalogCoverage(ctx, catalog, sourceID, from, to)
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(writer, "Catalog ownership for source %q (not live coverage):\n", coverage.SourceID)
	fmt.Fprintln(writer, "STATE\tPERIOD")
	for _, interval := range coverage.Covered {
		fmt.Fprintf(writer, "covered\t[%s, %s)\n", formatHistoryTime(interval.From), formatHistoryTime(interval.To))
	}
	for _, interval := range coverage.Gaps {
		fmt.Fprintf(writer, "gap\t[%s, %s)\n", formatHistoryTime(interval.From), formatHistoryTime(interval.To))
	}
	return writer.Flush()
}

func historyCatalogDetectionsCommand(ctx context.Context, args []string, out io.Writer) error {
	var catalog, fromText, toText string
	var limit int
	flags := flag.NewFlagSet("history catalog detections", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&catalog, "catalog", "", "historical coverage catalog SQLite path")
	flags.StringVar(&fromText, "from", "", "inclusive RFC3339 bound")
	flags.StringVar(&toText, "to", "", "exclusive RFC3339 bound")
	flags.IntVar(&limit, "limit", 100, "maximum detections (1-1000)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	from, to, err := parseHistoryPeriod(fromText, toText)
	if err != nil {
		return err
	}
	if flags.NArg() != 0 || catalog == "" {
		return fmt.Errorf("usage: antiddos history catalog detections --catalog FILE --from RFC3339 --to RFC3339 [--limit N]")
	}
	detections, err := history.ReadCatalogDetections(ctx, catalog, from, to, limit)
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "TIME\tIMPORT\tSOURCE\tRULE\tIP\tCOUNT\tTHRESHOLD")
	for _, detection := range detections {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%d\t%d\n", detection.EventTime.Format(time.RFC3339Nano), detection.ImportID, detection.LogSource, detection.RuleID, detection.TriggerIP, detection.RequestCount, detection.Threshold)
	}
	return writer.Flush()
}

func historyCatalogTrafficCommand(ctx context.Context, args []string, out io.Writer) error {
	var catalog, fromText, toText string
	flags := flag.NewFlagSet("history catalog traffic", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&catalog, "catalog", "", "historical coverage catalog SQLite path")
	flags.StringVar(&fromText, "from", "", "inclusive RFC3339 15-second boundary")
	flags.StringVar(&toText, "to", "", "exclusive RFC3339 15-second boundary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	from, to, err := parseHistoryPeriod(fromText, toText)
	if err != nil {
		return err
	}
	if catalog == "" {
		return fmt.Errorf("usage: antiddos history catalog traffic --catalog FILE --from RFC3339 --to RFC3339")
	}
	traffic, err := history.ReadCatalogTraffic(ctx, catalog, from, to)
	if err != nil {
		return err
	}
	var requests, matched, bytes, known int64
	for _, sample := range traffic.Samples {
		requests += sample.Requests
		matched += sample.MatchedRequests
		bytes += sample.ResponseBytes
		known += sample.KnownResponseByteRows
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "BUCKET\tREQUESTS\tMATCHED\tBYTES\tKNOWN BYTES")
	for _, sample := range traffic.Samples {
		fmt.Fprintf(writer, "%s\t%d\t%d\t%d\t%d\n", time.Unix(sample.BucketStartUnix, 0).Format(time.RFC3339), sample.Requests, sample.MatchedRequests, sample.ResponseBytes, sample.KnownResponseByteRows)
	}
	fmt.Fprintf(writer, "\nRegistered results: %d; requests: %d; matched: %d; bytes: %d; known byte rows: %d\n", traffic.Entries, requests, matched, bytes, known)
	return writer.Flush()
}

func historyCatalogListCommand(ctx context.Context, args []string, out io.Writer) error {
	var catalog string
	flags := flag.NewFlagSet("history catalog list", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&catalog, "catalog", "", "historical coverage catalog SQLite path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || catalog == "" {
		return fmt.Errorf("usage: antiddos history catalog list --catalog FILE")
	}
	entries, err := history.CatalogEntries(ctx, catalog)
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "IMPORT\tSOURCE\tPERIOD\tANALYSIS ID\tSHA-256\tRESULT")
	for _, entry := range entries {
		fmt.Fprintf(writer, "%s\t%s\t[%s, %s)\t%s\t%s\t%s\n", entry.ImportID, entry.SourceID, formatHistoryTime(entry.From), formatHistoryTime(entry.To), entry.AnalysisConfigID, entry.SHA256, entry.ResultPath)
	}
	return writer.Flush()
}

type coverageCandidate struct {
	database string
	item     storage.HistoryImportSummary
}

func historyPreflightCommand(ctx context.Context, args []string, out io.Writer) error {
	var databases []string
	flags := flag.NewFlagSet("history preflight", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.Func("database", "isolated historical SQLite result (repeat at least twice)", func(value string) error { databases = append(databases, value); return nil })
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(databases) < 2 {
		return fmt.Errorf("usage: antiddos history preflight --database FILE --database FILE [--database FILE...]")
	}
	candidates := make([]coverageCandidate, 0, len(databases))
	for _, database := range databases {
		reader, err := storage.OpenReader(database)
		if err != nil {
			return err
		}
		imports, readErr := reader.HistoryImports(ctx)
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(imports) != 1 {
			return fmt.Errorf("%q must contain exactly one historical import", database)
		}
		candidates = append(candidates, coverageCandidate{database, imports[0]})
	}
	if err := preflightCoverage(candidates); err != nil {
		return err
	}
	for _, candidate := range candidates {
		fmt.Fprintf(out, "Eligible: %s source=%s period=[%s, %s) import=%s\n", candidate.database, candidate.item.SourceID, formatHistoryTime(candidate.item.RequestedFrom), formatHistoryTime(candidate.item.RequestedTo), candidate.item.ID)
	}
	_, err := fmt.Fprintln(out, "No overlaps detected. This is a read-only preflight; it does not publish to shared history.")
	return err
}

func preflightCoverage(candidates []coverageCandidate) error {
	if len(candidates) < 2 {
		return fmt.Errorf("at least two historical results are required")
	}
	first := candidates[0].item
	for _, candidate := range candidates {
		item := candidate.item
		if !item.HasRequestedPeriod {
			return fmt.Errorf("%q has no explicit requested period; observed events alone cannot claim coverage", candidate.database)
		}
		if !item.WarmupComplete {
			return fmt.Errorf("%q has incomplete warm-up", candidate.database)
		}
		if item.SourceID != first.SourceID {
			return fmt.Errorf("%q has source %q, want %q", candidate.database, item.SourceID, first.SourceID)
		}
		if item.AnalysisConfigID == "" || item.AnalysisConfigID != first.AnalysisConfigID {
			return fmt.Errorf("%q has a different analysis config identity", candidate.database)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].item.RequestedFrom.Before(candidates[j].item.RequestedFrom) })
	for i := 1; i < len(candidates); i++ {
		previous, current := candidates[i-1], candidates[i]
		if current.item.RequestedFrom.Before(previous.item.RequestedTo) {
			return fmt.Errorf("coverage overlap: %q [%s, %s) and %q [%s, %s)", previous.database, formatHistoryTime(previous.item.RequestedFrom), formatHistoryTime(previous.item.RequestedTo), current.database, formatHistoryTime(current.item.RequestedFrom), formatHistoryTime(current.item.RequestedTo))
		}
	}
	return nil
}

func historyReportCommand(ctx context.Context, args []string, out io.Writer) error {
	var database string
	flags := flag.NewFlagSet("history report", flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&database, "database", "", "isolated historical SQLite result")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || database == "" {
		return fmt.Errorf("usage: antiddos history report --database FILE")
	}
	reader, err := storage.OpenReader(database)
	if err != nil {
		return err
	}
	defer reader.Close()
	imports, err := reader.HistoryImports(ctx)
	if err != nil {
		return err
	}
	if len(imports) == 0 {
		return fmt.Errorf("database contains no historical imports")
	}
	for _, item := range imports {
		coverage := "Coverage: observed events only; not eligible for shared-history ownership"
		if item.HasRequestedPeriod {
			coverage = fmt.Sprintf("Requested period: [%s, %s); warm-up from %s; complete: %t", formatHistoryTime(item.RequestedFrom), formatHistoryTime(item.RequestedTo), formatHistoryTime(item.WarmupFrom), item.WarmupComplete)
		}
		if _, err := fmt.Fprintf(out, "Import ID: %s\nSource: %s\nCreated: %s\nEvents: %s — %s\n%s\nFiles: %d; lines: %d; parsed: %d; ignored: %d; malformed: %d\n", item.ID, item.SourceID, item.CreatedAt.Format(time.RFC3339), formatHistoryTime(item.FirstEvent), formatHistoryTime(item.LastEvent), coverage, item.Files, item.Lines, item.Parsed, item.Ignored, item.Malformed); err != nil {
			return err
		}
	}
	counts, err := reader.HistoryRuleCounts(ctx)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Detections by rule:"); err != nil {
		return err
	}
	for _, count := range counts {
		if _, err := fmt.Fprintf(out, "  %s\t%d\n", count.RuleID, count.Count); err != nil {
			return err
		}
	}
	return nil
}

func historyImportCommand(ctx context.Context, args []string, out io.Writer) error {
	var configFile, sourceID, directory, nameRegex, outputPath, order, timezone, tempDirectory, fromText, toText, filenameTimeRegex, filenameTimeLayout string
	var syslogYear, maxFiles, maxLineBytes int
	var maxInputBytes, maxExpandedBytes, sortMemoryBytes, maxSortBytes, allowMalformed int64
	f := flag.NewFlagSet("history import", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&configFile, "config", configPath(), "configuration whose source and enabled rules are snapshotted")
	f.StringVar(&sourceID, "source", "", "configured logical log source")
	f.StringVar(&directory, "directory", "", "absolute directory containing archived logs")
	f.StringVar(&nameRegex, "name-regex", "", "Go RE2 expression matched against base filenames")
	f.StringVar(&outputPath, "output", "", "new isolated SQLite database (must not exist)")
	f.StringVar(&order, "order", history.OrderNatural, "discovery order: natural, lexical, first-event, or filename-time")
	f.StringVar(&filenameTimeRegex, "filename-time-regex", "", "RE2 with one capture group for timestamp in a base filename")
	f.StringVar(&filenameTimeLayout, "filename-time-layout", "", "Go time layout for --filename-time-regex capture")
	f.StringVar(&timezone, "timezone", "", "IANA timezone for records without an offset")
	f.IntVar(&syslogYear, "syslog-year", 0, "explicit year for legacy syslog records")
	f.IntVar(&maxFiles, "max-files", 1000, "maximum matched files")
	f.Int64Var(&maxInputBytes, "max-input-bytes", 100<<30, "maximum total compressed/input bytes")
	f.Int64Var(&maxExpandedBytes, "max-expanded-bytes", 200<<30, "maximum total expanded bytes")
	f.IntVar(&maxLineBytes, "max-line-bytes", 1<<20, "maximum bytes in one log line")
	f.Int64Var(&sortMemoryBytes, "sort-memory-bytes", 256<<20, "approximate in-memory external-sort chunk size")
	f.Int64Var(&maxSortBytes, "max-sort-bytes", 50<<30, "maximum temporary external-sort disk usage")
	f.StringVar(&tempDirectory, "temp-directory", "", "existing directory for external-sort chunks (defaults beside output)")
	f.Int64Var(&allowMalformed, "allow-malformed", 0, "explicit maximum malformed lines which may be skipped")
	f.StringVar(&fromText, "from", "", "period start, inclusive (RFC3339; requires --to)")
	f.StringVar(&toText, "to", "", "period end, exclusive (RFC3339; requires --from)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	from, to, err := parseHistoryPeriod(fromText, toText)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	var location *time.Location
	if timezone != "" {
		location, err = time.LoadLocation(timezone)
		if err != nil {
			return fmt.Errorf("load timezone %q: %w", timezone, err)
		}
	}
	fmt.Fprintf(out, "Historical import started: source=%s output=%s; actions and live database are disabled.\n", sourceID, outputPath)
	result, err := history.Import(ctx, history.ImportOptions{
		Config: cfg, SourceID: sourceID, Directory: directory, NameRegex: nameRegex, OutputPath: outputPath,
		Order: order, Location: location, SyslogYear: syslogYear, MaxFiles: maxFiles,
		MaxInputBytes: maxInputBytes, MaxExpandedBytes: maxExpandedBytes, MaxLineBytes: maxLineBytes,
		SortMemoryBytes: sortMemoryBytes, MaxSortBytes: maxSortBytes, TempDirectory: tempDirectory, AllowMalformed: allowMalformed,
		From: from, To: to,
		FilenameTimeRegex: filenameTimeRegex, FilenameTimeLayout: filenameTimeLayout,
		Progress: func(progress history.ImportProgress) {
			if progress.Stage == "read-sort" {
				fmt.Fprintf(out, "Read/sorted files: %d; lines: %d; parsed: %d\n", progress.Files, progress.Lines, progress.Parsed)
			} else {
				fmt.Fprintf(out, "Analyzed: %d/%d events; detections: %d\n", progress.Processed, progress.Parsed, progress.Detections)
			}
		},
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Published %s\nImport ID: %s\nFiles: %d; lines: %d; parsed: %d; ignored: %d; malformed: %d; published events: %d; warm-up events: %d; detections: %d\nInput period: %s — %s\n",
		result.OutputPath, result.ImportID, result.Files, result.Lines, result.Parsed, result.Ignored, result.Malformed,
		result.Published, result.Warmup, result.Detections, formatHistoryTime(result.FirstEvent), formatHistoryTime(result.LastEvent))
	if err != nil {
		return err
	}
	if !result.From.IsZero() {
		_, err = fmt.Fprintf(out, "Published period: [%s, %s); warm-up from %s; complete: %t\n",
			formatHistoryTime(result.From), formatHistoryTime(result.To), formatHistoryTime(result.WarmupFrom), result.WarmupComplete)
	}
	return err
}

func parseHistoryPeriod(fromText, toText string) (time.Time, time.Time, error) {
	if fromText == "" && toText == "" {
		return time.Time{}, time.Time{}, nil
	}
	if fromText == "" || toText == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("--from and --to must be supplied together")
	}
	from, err := time.Parse(time.RFC3339, fromText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse --from as RFC3339: %w", err)
	}
	to, err := time.Parse(time.RFC3339, toText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse --to as RFC3339: %w", err)
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("history period must satisfy --from < --to")
	}
	return from, to, nil
}

func historyPreviewCommand(ctx context.Context, args []string, out io.Writer) error {
	var directory, nameRegex, format, logFormat, order, timezone, filenameTimeRegex, filenameTimeLayout string
	var syslogYear, maxFiles, maxLineBytes int
	var maxInputBytes, maxExpandedBytes int64
	f := flag.NewFlagSet("history preview", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&directory, "directory", "", "absolute directory containing logs")
	f.StringVar(&nameRegex, "name-regex", "", "Go RE2 expression matched against base filenames")
	f.StringVar(&format, "format", parser.FormatNginxCombined, "configured log format")
	f.StringVar(&logFormat, "log-format", "", "nginx_custom log_format")
	f.StringVar(&order, "order", history.OrderNatural, "file order: natural, lexical, first-event, or filename-time")
	f.StringVar(&filenameTimeRegex, "filename-time-regex", "", "RE2 with one capture group for timestamp in a base filename")
	f.StringVar(&filenameTimeLayout, "filename-time-layout", "", "Go time layout for --filename-time-regex capture")
	f.StringVar(&timezone, "timezone", "", "IANA timezone for records without an offset")
	f.IntVar(&syslogYear, "syslog-year", 0, "explicit year for legacy syslog records")
	f.IntVar(&maxFiles, "max-files", 1000, "maximum matched files")
	f.Int64Var(&maxInputBytes, "max-input-bytes", 100<<30, "maximum total compressed/input bytes")
	f.Int64Var(&maxExpandedBytes, "max-expanded-bytes", 200<<30, "maximum total expanded bytes")
	f.IntVar(&maxLineBytes, "max-line-bytes", 1<<20, "maximum bytes in one log line")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	var location *time.Location
	if timezone != "" {
		loaded, err := time.LoadLocation(timezone)
		if err != nil {
			return fmt.Errorf("load timezone %q: %w", timezone, err)
		}
		location = loaded
	}
	report, err := history.Preview(ctx, history.PreviewOptions{
		Directory: directory, NameRegex: nameRegex, Format: format, LogFormat: logFormat,
		Order: order, Location: location, SyslogYear: syslogYear, MaxFiles: maxFiles,
		FilenameTimeRegex: filenameTimeRegex, FilenameTimeLayout: filenameTimeLayout,
		MaxInputBytes: maxInputBytes, MaxExpandedBytes: maxExpandedBytes, MaxLineBytes: maxLineBytes,
	})
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "#\tFILE\tBYTES\tTYPE\tLINES\tPARSED\tIGNORED\tMALFORMED\tFIRST EVENT\tLAST EVENT\tUNSORTED\tERROR")
	errorsFound := 0
	for index, file := range report.Files {
		kind := "text"
		if file.Compressed {
			kind = "gzip"
		}
		errorText := "-"
		if file.Err != nil {
			errorText = file.Err.Error()
			errorsFound++
		}
		fmt.Fprintf(writer, "%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%s\n",
			index+1, file.Path, file.Size, kind, file.Lines, file.Parsed, file.Ignored, file.Malformed,
			formatHistoryTime(file.FirstEvent), formatHistoryTime(file.LastEvent), file.OutOfOrderLines, errorText)
	}
	fmt.Fprintf(writer, "\nMatched %d files (%d input bytes); read %d expanded bytes; parsed %d, ignored %d, malformed %d of %d lines; adjacent overlaps: %d.\n",
		len(report.Files), report.TotalSize, report.ExpandedBytes, report.Parsed, report.Ignored, report.Malformed, report.Lines, report.Overlapping)
	estimate := report.ExpandedBytes * 4
	if estimate < 256<<20 {
		estimate = 256 << 20
	}
	fmt.Fprintf(writer, "Conservative sort/output estimate: %d bytes plus 1073741824 bytes reserve on each selected filesystem.\n", estimate)
	fmt.Fprintf(writer, "Filename regex scope: %s. No data was imported.\n", report.NameMatchScope)
	if err := writer.Flush(); err != nil {
		return err
	}
	if errorsFound > 0 {
		return fmt.Errorf("preview found read errors in %d files", errorsFound)
	}
	return nil
}

func formatHistoryTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(time.RFC3339)
}
