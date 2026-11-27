package history

import (
	"bufio"
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/request"
	"github.com/it-nsk/antiddos/internal/storage"
)

const importAlgorithmVersion = "history-import-v4-response-time-published"

type ImportOptions struct {
	Config              config.Config
	SourceID            string
	Directory           string
	AllowedRoots        []string
	NameRegex           string
	OutputPath          string
	Order               string
	FilenameTimeRegex   string
	FilenameTimeLayout  string
	Location            *time.Location
	SyslogYear          int
	MaxFiles            int
	MaxInputBytes       int64
	MaxExpandedBytes    int64
	MaxLineBytes        int
	SortMemoryBytes     int64
	MaxSortBytes        int64
	PreflightBytes      int64
	TempDirectory       string
	AllowMalformed      int64
	From                time.Time
	To                  time.Time
	Progress            func(ImportProgress)
	ComparisonRule      string
	ParentImportID      string
	CurrentSnapshotPath string
}

type ImportProgress struct {
	Stage      string `json:"stage"`
	Files      int64  `json:"files"`
	Lines      int64  `json:"lines"`
	Parsed     int64  `json:"parsed"`
	Processed  int64  `json:"processed"`
	Detections int64  `json:"detections"`
}

type ImportResult struct {
	ImportID       string    `json:"import_id"`
	OutputPath     string    `json:"output_path"`
	Files          int64     `json:"files"`
	Lines          int64     `json:"lines"`
	Parsed         int64     `json:"parsed"`
	Ignored        int64     `json:"ignored"`
	Malformed      int64     `json:"malformed"`
	Detections     int64     `json:"detections"`
	Published      int64     `json:"published"`
	Warmup         int64     `json:"warmup"`
	FirstEvent     time.Time `json:"first_event"`
	LastEvent      time.Time `json:"last_event"`
	From           time.Time `json:"from,omitempty"`
	To             time.Time `json:"to,omitempty"`
	WarmupFrom     time.Time `json:"warmup_from,omitempty"`
	WarmupComplete bool      `json:"warmup_complete"`
}

type importManifest struct {
	Version          string         `json:"version"`
	ImportID         string         `json:"import_id"`
	SourceID         string         `json:"source_id"`
	ComparisonRule   string         `json:"comparison_rule,omitempty"`
	ParentImportID   string         `json:"parent_import_id,omitempty"`
	Format           string         `json:"format"`
	LogFormat        string         `json:"log_format,omitempty"`
	Timezone         string         `json:"timezone,omitempty"`
	SyslogYear       int            `json:"syslog_year,omitempty"`
	NameRegex        string         `json:"name_regex"`
	AnalysisConfigID string         `json:"analysis_config_id"`
	GlobalIgnoreIPs  []string       `json:"global_ignore_ips,omitempty"`
	Rules            []manifestRule `json:"rules"`
	From             string         `json:"from,omitempty"`
	To               string         `json:"to,omitempty"`
	WarmupFrom       string         `json:"warmup_from,omitempty"`
	WarmupComplete   bool           `json:"warmup_complete"`
	Files            []manifestFile `json:"files"`
}

type manifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// manifestRule is an immutable, reviewable snapshot of every setting that
// can affect a historical detection. Actions are intentionally excluded:
// history never routes enforcement.
type manifestRule struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	LogSource  string   `json:"log_source"`
	PathRegex  string   `json:"path_regex"`
	QueryRegex string   `json:"query_regex,omitempty"`
	Statuses   []int    `json:"statuses,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	UniqueBy   string   `json:"unique_by,omitempty"`
	WindowNS   int64    `json:"window_ns"`
	Threshold  int      `json:"threshold"`
	GroupBy    string   `json:"group_by"`
	IgnoreIPs  []string `json:"ignore_ips,omitempty"`
}

type sortRecord struct {
	TimestampUnixNano  int64
	ZoneName           string
	ZoneOffset         int
	IP                 string
	Method             string
	Path               string
	RawQuery           string
	Protocol           string
	Status             int
	ResponseOrigin     string
	ResponseBytes      int64
	HasResponseBytes   bool
	ResponseTimeMillis int64
	HasResponseTime    bool
	UserAgent          string
	RawLine            string
	FileOrdinal        int
	LineNumber         int64
}

func Import(ctx context.Context, options ImportOptions) (ImportResult, error) {
	if err := validateImportOptions(options); err != nil {
		return ImportResult{}, err
	}
	source, rules, err := importSourceAndRules(options.Config, options.SourceID)
	if err != nil {
		return ImportResult{}, err
	}
	logParser, err := parser.NewHistorical(source.Format, source.LogFormat, parser.HistoricalOptions{Location: options.Location, SyslogYear: options.SyslogYear})
	if err != nil {
		return ImportResult{}, fmt.Errorf("configure historical parser: %w", err)
	}
	ruleEngine, err := engine.NewWithOptions(rules, engine.Options{IgnoreIPs: options.Config.Engine.IgnoreIPs})
	if err != nil {
		return ImportResult{}, fmt.Errorf("initialize historical engine: %w", err)
	}
	previewOptions := PreviewOptions{
		Directory: options.Directory, AllowedRoots: options.AllowedRoots, NameRegex: options.NameRegex, Format: source.Format, LogFormat: source.LogFormat,
		Order: options.Order, FilenameTimeRegex: options.FilenameTimeRegex, FilenameTimeLayout: options.FilenameTimeLayout, Location: options.Location, SyslogYear: options.SyslogYear, MaxFiles: options.MaxFiles,
		MaxInputBytes: options.MaxInputBytes, MaxExpandedBytes: options.MaxExpandedBytes, MaxLineBytes: options.MaxLineBytes,
	}
	var live candidate
	var liveSnapshot *os.File
	if options.CurrentSnapshotPath != "" {
		live, err = openLiveSnapshot(options.CurrentSnapshotPath)
		if err != nil {
			return ImportResult{}, err
		}
		liveSnapshot = live.liveSnapshot
		defer liveSnapshot.Close()
	}
	files, _, err := discover(previewOptions)
	if err != nil {
		if liveSnapshot == nil || !strings.Contains(err.Error(), "no regular files matched the filename regex") {
			return ImportResult{}, err
		}
		files = nil
	}
	if liveSnapshot != nil {
		if len(files) >= options.MaxFiles {
			return ImportResult{}, fmt.Errorf("current log snapshot exceeds file limit of %d", options.MaxFiles)
		}
		var discoveredBytes int64
		for _, file := range files {
			if os.SameFile(file.info, live.info) {
				return ImportResult{}, fmt.Errorf("current log %q is already matched by --name-regex; exclude it when using --snapshot-current", live.path)
			}
			discoveredBytes += file.size
		}
		if live.size > options.MaxInputBytes-discoveredBytes {
			return ImportResult{}, fmt.Errorf("current log snapshot exceeds input size limit of %d bytes", options.MaxInputBytes)
		}
		files = append(files, live)
	}
	// Size the preflight to this archive. MaxSortBytes remains the hard cap
	// enforced while writing chunks, rather than a fixed space requirement.
	var inputBytes int64
	for _, file := range files {
		inputBytes += file.size
	}
	estimatedSortBytes := inputBytes * 8
	if estimatedSortBytes < 256<<20 {
		estimatedSortBytes = 256 << 20
	}
	if estimatedSortBytes > options.MaxSortBytes {
		estimatedSortBytes = options.MaxSortBytes
	}
	if options.PreflightBytes > estimatedSortBytes {
		estimatedSortBytes = options.PreflightBytes
	}

	tempRoot := options.TempDirectory
	if tempRoot == "" {
		tempRoot = filepath.Dir(options.OutputPath)
	}
	if err := preflightWorkspace(tempRoot, estimatedSortBytes); err != nil {
		return ImportResult{}, err
	}
	if filepath.Clean(tempRoot) != filepath.Clean(filepath.Dir(options.OutputPath)) {
		if err := preflightWorkspace(filepath.Dir(options.OutputPath), estimatedSortBytes/2); err != nil {
			return ImportResult{}, fmt.Errorf("output filesystem: %w", err)
		}
	}
	sortDirectory, err := os.MkdirTemp(tempRoot, ".antiddos-history-sort-")
	if err != nil {
		return ImportResult{}, fmt.Errorf("create sort directory: %w", err)
	}
	defer os.RemoveAll(sortDirectory)

	result := ImportResult{OutputPath: options.OutputPath, Files: int64(len(files))}
	chunks, manifestFiles, err := buildSortChunks(ctx, files, logParser, previewOptions, options, sortDirectory, &result)
	if err != nil {
		return ImportResult{}, err
	}
	if result.Parsed == 0 {
		return ImportResult{}, fmt.Errorf("no supported events were parsed; refusing to publish an empty history database")
	}
	// The normal flow deliberately has no manually entered period.  The
	// observed range is the ownership range; the final nanosecond makes its
	// half-open end include the final event.  There is no earlier archive data
	// to warm the first engine window, so preserve that fact as provenance.
	if result.From.IsZero() {
		result.From = result.FirstEvent
		result.To = result.LastEvent.Add(time.Nanosecond)
		result.WarmupFrom = result.From.Add(-maximumRuleWindow(rules))
		result.WarmupComplete = false
	}

	analysisConfigID := engine.AnalysisConfigID(ruleEngine.RuleRevisions())
	if !options.From.IsZero() {
		result.From, result.To = options.From, options.To
	}
	if !options.From.IsZero() {
		result.WarmupFrom = options.From.Add(-maximumRuleWindow(rules))
		result.WarmupComplete = !result.FirstEvent.After(result.WarmupFrom)
	}
	manifest := importManifest{
		Version: importAlgorithmVersion, SourceID: options.SourceID, ComparisonRule: options.ComparisonRule, ParentImportID: options.ParentImportID, Format: source.Format, LogFormat: source.LogFormat,
		SyslogYear: options.SyslogYear, NameRegex: options.NameRegex, AnalysisConfigID: analysisConfigID,
		GlobalIgnoreIPs: canonicalStrings(options.Config.Engine.IgnoreIPs), Rules: snapshotRules(rules), Files: manifestFiles,
		WarmupComplete: result.WarmupComplete,
	}
	if !result.From.IsZero() {
		manifest.From = result.From.UTC().Format(time.RFC3339Nano)
		manifest.To = result.To.UTC().Format(time.RFC3339Nano)
		manifest.WarmupFrom = result.WarmupFrom.UTC().Format(time.RFC3339Nano)
	}
	if options.Location != nil {
		manifest.Timezone = options.Location.String()
	}
	identityDocument, err := json.Marshal(manifest)
	if err != nil {
		return ImportResult{}, fmt.Errorf("encode import identity: %w", err)
	}
	identity := sha256.Sum256(identityDocument)
	result.ImportID = hex.EncodeToString(identity[:])
	manifest.ImportID = result.ImportID
	manifestDocument, err := json.Marshal(manifest)
	if err != nil {
		return ImportResult{}, fmt.Errorf("encode import manifest: %w", err)
	}

	stagingPath, err := newStagingPath(options.OutputPath)
	if err != nil {
		return ImportResult{}, err
	}
	published := false
	defer func() {
		if !published {
			removeSQLiteFiles(stagingPath)
		}
	}()
	store, err := storage.Open(stagingPath)
	if err != nil {
		return ImportResult{}, fmt.Errorf("open staging database: %w", err)
	}
	batch, err := store.BeginHistoryBatch(ctx, result.ImportID)
	if err != nil {
		store.Close()
		return ImportResult{}, err
	}
	collector := metrics.NewCollector()
	var processed int64
	processErr := mergeChunks(ctx, chunks, func(record sortRecord) error {
		event, err := record.event()
		if err != nil {
			return err
		}
		if !options.From.IsZero() && event.Timestamp.Before(result.WarmupFrom) {
			return nil
		}
		if !options.To.IsZero() && !event.Timestamp.Before(options.To) {
			return nil
		}
		evaluations, matched, err := ruleEngine.ProcessWithMatch(event)
		if err != nil {
			return fmt.Errorf("process sorted event: %w", err)
		}
		processed++
		if !options.From.IsZero() && event.Timestamp.Before(options.From) {
			result.Warmup++
			return nil
		}
		result.Published++
		collector.Add(options.SourceID, event, matched)
		for _, evaluation := range evaluations {
			if evaluation.Detection == nil {
				continue
			}
			if err := batch.RecordDetection(ctx, *evaluation.Detection, event); err != nil {
				return err
			}
			result.Detections++
		}
		if options.Progress != nil && processed%1_000_000 == 0 {
			options.Progress(ImportProgress{Stage: "analyze", Files: result.Files, Lines: result.Lines, Parsed: result.Parsed, Processed: processed, Detections: result.Detections})
		}
		return nil
	})
	if processErr == nil {
		processErr = collector.Flush(ctx, batch)
	}
	if processErr == nil {
		processErr = batch.RecordImport(ctx, storage.HistoryImportRecord{
			ID: result.ImportID, SourceID: options.SourceID, CreatedAt: time.Now(), FirstEvent: result.FirstEvent, LastEvent: result.LastEvent,
			Files: result.Files, Lines: result.Lines, Parsed: result.Parsed, Ignored: result.Ignored, Malformed: result.Malformed,
			ManifestJSON: string(manifestDocument),
		})
	}
	if processErr == nil {
		processErr = batch.RecordCoverage(ctx, storage.HistoryCoverageRecord{ImportID: result.ImportID, SourceID: options.SourceID, AnalysisConfigID: analysisConfigID, ObservedFrom: result.FirstEvent, ObservedTo: result.LastEvent, RequestedFrom: result.From, RequestedTo: result.To, WarmupFrom: result.WarmupFrom, WarmupComplete: result.WarmupComplete})
	}
	if processErr == nil {
		processErr = batch.Commit()
	} else {
		_ = batch.Rollback()
	}
	closeErr := store.Close()
	if processErr != nil {
		return ImportResult{}, processErr
	}
	if closeErr != nil {
		return ImportResult{}, fmt.Errorf("close staging database: %w", closeErr)
	}
	// Hard-link publication is atomic and, unlike os.Rename on Unix, refuses
	// to replace a destination which appeared while the long import was running.
	if err := os.Link(stagingPath, options.OutputPath); err != nil {
		return ImportResult{}, fmt.Errorf("publish history database: %w", err)
	}
	published = true
	_ = os.Remove(stagingPath)
	if directory, err := os.Open(filepath.Dir(options.OutputPath)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return result, nil
}

func validateImportOptions(options ImportOptions) error {
	if options.SourceID == "" {
		return fmt.Errorf("source ID must not be empty")
	}
	if !filepath.IsAbs(options.OutputPath) {
		return fmt.Errorf("output SQLite path must be absolute")
	}
	if options.Config.DatabasePath != "" && filepath.Clean(options.OutputPath) == filepath.Clean(options.Config.DatabasePath) {
		return fmt.Errorf("output path must not be the configured live database")
	}
	if _, err := os.Lstat(options.OutputPath); err == nil {
		return fmt.Errorf("output path %q already exists; refusing to overwrite", options.OutputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	if options.SortMemoryBytes < 1 || options.MaxSortBytes < 1 || options.AllowMalformed < 0 {
		return fmt.Errorf("sort limits must be positive and allow-malformed must not be negative")
	}
	if options.From.IsZero() != options.To.IsZero() {
		return fmt.Errorf("from and to must be supplied together")
	}
	if !options.From.IsZero() && !options.From.Before(options.To) {
		return fmt.Errorf("history period must satisfy from < to")
	}
	return validateOptions(PreviewOptions{
		Directory: options.Directory, AllowedRoots: options.AllowedRoots, NameRegex: options.NameRegex, Order: options.Order,
		FilenameTimeRegex: options.FilenameTimeRegex, FilenameTimeLayout: options.FilenameTimeLayout,
		MaxFiles: options.MaxFiles, MaxInputBytes: options.MaxInputBytes,
		MaxExpandedBytes: options.MaxExpandedBytes, MaxLineBytes: options.MaxLineBytes,
	})
}

// openLiveSnapshot pins the active log inode and its byte boundary.  The
// importer streams that descriptor directly, so no second full-size copy is
// written and appends after this point cannot enter the historical run.
func openLiveSnapshot(path string) (candidate, error) {
	if !filepath.IsAbs(path) {
		return candidate{}, fmt.Errorf("current log path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return candidate{}, fmt.Errorf("stat current log %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return candidate{}, fmt.Errorf("current log %q must be a regular non-symlink file", path)
	}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		return candidate{}, fmt.Errorf("current log snapshot does not support gzip files")
	}
	opened, err := os.Open(path)
	if err != nil {
		return candidate{}, fmt.Errorf("open current log %q: %w", path, err)
	}
	openedInfo, err := opened.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		opened.Close()
		return candidate{}, fmt.Errorf("current log %q changed while opening", path)
	}
	return candidate{path: path, name: filepath.Base(path), size: openedInfo.Size(), info: openedInfo, liveSnapshot: opened}, nil
}

func maximumRuleWindow(rules []engine.Rule) time.Duration {
	var maximum time.Duration
	for _, rule := range rules {
		if rule.Window > maximum {
			maximum = rule.Window
		}
	}
	return maximum
}

func snapshotRules(rules []engine.Rule) []manifestRule {
	result := make([]manifestRule, 0, len(rules))
	for _, rule := range rules {
		statuses := append([]int(nil), rule.Statuses...)
		sort.Ints(statuses)
		result = append(result, manifestRule{
			ID: rule.ID, Type: rule.Type, LogSource: rule.LogSource, PathRegex: rule.PathRegex,
			QueryRegex: rule.QueryRegex, Statuses: statuses, Methods: canonicalStrings(rule.Methods), UniqueBy: rule.UniqueBy,
			WindowNS: int64(rule.Window), Threshold: rule.Threshold, GroupBy: string(rule.GroupBy),
			IgnoreIPs: canonicalStrings(rule.IgnoreIPs),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func canonicalStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func importSourceAndRules(cfg config.Config, sourceID string) (config.LogSourceConfig, []engine.Rule, error) {
	var source config.LogSourceConfig
	for _, candidate := range cfg.LogSources {
		if candidate.ID == sourceID {
			source = candidate
			break
		}
	}
	if source.ID == "" {
		return source, nil, fmt.Errorf("unknown log source %q", sourceID)
	}
	rules := make([]engine.Rule, 0)
	for _, configured := range cfg.Engine.Rules {
		if configured.LogSource != sourceID || configured.ExplicitlyDisabled {
			continue
		}
		rules = append(rules, engine.Rule{
			ID: configured.ID, Type: configured.Type, LogSource: configured.LogSource, PathRegex: configured.PathRegex,
			QueryRegex: configured.QueryRegex, Statuses: configured.Statuses, Methods: configured.Methods, UniqueBy: configured.UniqueBy,
			Window: configured.Window, Threshold: configured.Threshold, GroupBy: engine.GroupField(configured.GroupBy), IgnoreIPs: configured.IgnoreIPs,
		})
	}
	if len(rules) == 0 {
		return source, nil, fmt.Errorf("source %q has no enabled rules", sourceID)
	}
	return source, rules, nil
}

func buildSortChunks(ctx context.Context, files []candidate, logParser parser.Parser, preview PreviewOptions, options ImportOptions, directory string, result *ImportResult) ([]string, []manifestFile, error) {
	var records []sortRecord
	var memoryBytes, diskBytes int64
	var chunks []string
	manifests := make([]manifestFile, 0, len(files))
	remainingExpanded := preview.MaxExpandedBytes
	flush := func() error {
		if len(records) == 0 {
			return nil
		}
		sort.Slice(records, func(i, j int) bool { return recordLess(records[i], records[j]) })
		path, size, err := writeChunk(directory, records)
		if err != nil {
			return err
		}
		diskBytes += size
		if diskBytes > options.MaxSortBytes {
			return fmt.Errorf("external sort exceeds disk limit of %d bytes", options.MaxSortBytes)
		}
		chunks = append(chunks, path)
		records = nil
		memoryBytes = 0
		return nil
	}
	for fileOrdinal, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var err error
		opened := file.liveSnapshot
		if opened == nil {
			opened, err = os.Open(file.path)
			if err != nil {
				return nil, nil, fmt.Errorf("open %q: %w", file.path, err)
			}
		}
		openedInfo, err := opened.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(file.info, openedInfo) || (file.liveSnapshot == nil && (openedInfo.Size() != file.size || !openedInfo.ModTime().Equal(file.info.ModTime()))) || (file.liveSnapshot != nil && openedInfo.Size() < file.size) {
			return nil, nil, fmt.Errorf("file %q changed after discovery", file.path)
		}
		if file.liveSnapshot != nil {
			if _, err := opened.Seek(0, io.SeekStart); err != nil {
				return nil, nil, fmt.Errorf("rewind current log snapshot %q: %w", file.path, err)
			}
		}
		hasher := sha256.New()
		var raw io.Reader = opened
		if file.liveSnapshot != nil {
			raw = io.LimitReader(opened, file.size)
		}
		physical := io.TeeReader(raw, hasher)
		var source io.Reader = physical
		var gzipReader *gzip.Reader
		if file.compressed {
			gzipReader, err = gzip.NewReader(physical)
			if err != nil {
				opened.Close()
				return nil, nil, fmt.Errorf("open gzip %q: %w", file.path, err)
			}
			source = gzipReader
		}
		limited := &io.LimitedReader{R: source, N: remainingExpanded + 1}
		scanner := bufio.NewScanner(limited)
		scanner.Buffer(make([]byte, min(preview.MaxLineBytes, 64*1024)), preview.MaxLineBytes)
		var lineNumber int64
		for scanner.Scan() {
			lineNumber++
			result.Lines++
			if options.Progress != nil && result.Lines%10_000 == 0 {
				options.Progress(ImportProgress{Stage: "read-sort", Files: int64(fileOrdinal), Lines: result.Lines, Parsed: result.Parsed})
			}
			if err := ctx.Err(); err != nil {
				opened.Close()
				return nil, nil, err
			}
			line := scanner.Text()
			event, parseErr := logParser.Parse(line)
			if parseErr != nil {
				if parser.IsIgnored(parseErr) {
					result.Ignored++
				} else {
					result.Malformed++
					if result.Malformed > options.AllowMalformed {
						return nil, nil, fmt.Errorf("malformed line allowance exceeded at %s:%d (%d > %d)", file.path, lineNumber, result.Malformed, options.AllowMalformed)
					}
				}
				continue
			}
			event.RawLine = line
			record := newSortRecord(event, fileOrdinal, lineNumber)
			records = append(records, record)
			memoryBytes += record.approximateBytes()
			result.Parsed++
			if result.FirstEvent.IsZero() || event.Timestamp.Before(result.FirstEvent) {
				result.FirstEvent = event.Timestamp
			}
			if result.LastEvent.IsZero() || event.Timestamp.After(result.LastEvent) {
				result.LastEvent = event.Timestamp
			}
			if memoryBytes >= options.SortMemoryBytes {
				if err := flush(); err != nil {
					return nil, nil, err
				}
			}
		}
		expanded := remainingExpanded + 1 - limited.N
		remainingExpanded -= min(expanded, remainingExpanded)
		if limited.N <= 0 {
			return nil, nil, fmt.Errorf("expanded data exceeds limit of %d bytes", preview.MaxExpandedBytes)
		}
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("read %q: %w", file.path, err)
		}
		if gzipReader != nil {
			if err := gzipReader.Close(); err != nil {
				return nil, nil, fmt.Errorf("close gzip %q: %w", file.path, err)
			}
		}
		if file.liveSnapshot == nil {
			if _, err := io.Copy(io.Discard, physical); err != nil {
				return nil, nil, fmt.Errorf("fingerprint %q: %w", file.path, err)
			}
		}
		finalInfo, err := opened.Stat()
		if err != nil || (file.liveSnapshot == nil && (finalInfo.Size() != openedInfo.Size() || !finalInfo.ModTime().Equal(openedInfo.ModTime()))) || (file.liveSnapshot != nil && finalInfo.Size() < file.size) {
			return nil, nil, fmt.Errorf("file %q changed while it was being read", file.path)
		}
		if file.liveSnapshot == nil {
			if err := opened.Close(); err != nil {
				return nil, nil, fmt.Errorf("close %q: %w", file.path, err)
			}
		}
		manifests = append(manifests, manifestFile{Path: file.path, Size: file.size, SHA256: hex.EncodeToString(hasher.Sum(nil))})
		if options.Progress != nil {
			options.Progress(ImportProgress{Stage: "read-sort", Files: int64(fileOrdinal + 1), Lines: result.Lines, Parsed: result.Parsed})
		}
	}
	if err := flush(); err != nil {
		return nil, nil, err
	}
	return chunks, manifests, nil
}

// preflightWorkspace prevents the historical external sort from filling an
// incidental tmpfs.  The caller supplies an explicit durable directory; a
// fixed reserve leaves room for SQLite journals and the running system.
func preflightWorkspace(directory string, sortLimit int64) error {
	if !filepath.IsAbs(directory) {
		return fmt.Errorf("history work directory must be absolute")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(directory, &stat); err != nil {
		return fmt.Errorf("stat history work directory: %w", err)
	}
	const reserve = int64(1 << 30)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	if available < reserve || sortLimit > available-reserve {
		return fmt.Errorf("insufficient free space in history work directory: available=%d reserve=%d required-sort-limit=%d", available, reserve, sortLimit)
	}
	return nil
}

func newSortRecord(event request.Event, fileOrdinal int, lineNumber int64) sortRecord {
	zoneName, zoneOffset := event.Timestamp.Zone()
	record := sortRecord{
		TimestampUnixNano: event.Timestamp.UnixNano(), ZoneName: zoneName, ZoneOffset: zoneOffset,
		IP: event.IP.String(), Method: event.Method, Path: event.Path, RawQuery: event.RawQuery,
		Protocol: event.Protocol, Status: event.Status, ResponseOrigin: event.ResponseOrigin,
		UserAgent: event.UserAgent, RawLine: event.RawLine, FileOrdinal: fileOrdinal, LineNumber: lineNumber,
	}
	if event.ResponseBytes != nil {
		record.HasResponseBytes = true
		record.ResponseBytes = *event.ResponseBytes
	}
	if event.ResponseTimeMillis != nil {
		record.HasResponseTime = true
		record.ResponseTimeMillis = *event.ResponseTimeMillis
	}
	return record
}

func (record sortRecord) event() (request.Event, error) {
	ip, err := netip.ParseAddr(record.IP)
	if err != nil {
		return request.Event{}, fmt.Errorf("decode sorted IP: %w", err)
	}
	timestamp := time.Unix(0, record.TimestampUnixNano).In(time.FixedZone(record.ZoneName, record.ZoneOffset))
	event := request.Event{
		Timestamp: timestamp, IP: ip, Method: record.Method, Path: record.Path, RawQuery: record.RawQuery,
		Query: url.Values{}, Protocol: record.Protocol, Status: record.Status, ResponseOrigin: record.ResponseOrigin,
		UserAgent: record.UserAgent, RawLine: record.RawLine,
	}
	if record.RawQuery != "" {
		event.Query, _ = url.ParseQuery(record.RawQuery)
	}
	if record.HasResponseBytes {
		value := record.ResponseBytes
		event.ResponseBytes = &value
	}
	if record.HasResponseTime {
		value := record.ResponseTimeMillis
		event.ResponseTimeMillis = &value
	}
	return event, nil
}

func (record sortRecord) approximateBytes() int64 {
	return int64(192 + len(record.IP) + len(record.Method) + len(record.Path) + len(record.RawQuery) + len(record.Protocol) + len(record.ResponseOrigin) + len(record.UserAgent) + len(record.RawLine))
}

func recordLess(left, right sortRecord) bool {
	if left.TimestampUnixNano != right.TimestampUnixNano {
		return left.TimestampUnixNano < right.TimestampUnixNano
	}
	if left.FileOrdinal != right.FileOrdinal {
		return left.FileOrdinal < right.FileOrdinal
	}
	return left.LineNumber < right.LineNumber
}

func writeChunk(directory string, records []sortRecord) (string, int64, error) {
	file, err := os.CreateTemp(directory, "chunk-*.gob")
	if err != nil {
		return "", 0, fmt.Errorf("create sort chunk: %w", err)
	}
	path := file.Name()
	writer := bufio.NewWriterSize(file, 256*1024)
	encoder := gob.NewEncoder(writer)
	for index := range records {
		if err := encoder.Encode(&records[index]); err != nil {
			file.Close()
			return "", 0, fmt.Errorf("encode sort chunk: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return "", 0, fmt.Errorf("flush sort chunk: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", 0, fmt.Errorf("sync sort chunk: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return "", 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, err
	}
	return path, info.Size(), nil
}

type chunkStream struct {
	file    *os.File
	decoder *gob.Decoder
	record  sortRecord
	index   int
}

type mergeHeap []*chunkStream

func (items mergeHeap) Len() int           { return len(items) }
func (items mergeHeap) Less(i, j int) bool { return recordLess(items[i].record, items[j].record) }
func (items mergeHeap) Swap(i, j int)      { items[i], items[j] = items[j], items[i] }
func (items *mergeHeap) Push(value any)    { *items = append(*items, value.(*chunkStream)) }
func (items *mergeHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	*items = old[:len(old)-1]
	return last
}

func mergeChunks(ctx context.Context, paths []string, consume func(sortRecord) error) error {
	streams := make([]*chunkStream, 0, len(paths))
	queue := mergeHeap{}
	defer func() {
		for _, stream := range streams {
			_ = stream.file.Close()
		}
	}()
	for index, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open sort chunk: %w", err)
		}
		stream := &chunkStream{file: file, decoder: gob.NewDecoder(bufio.NewReaderSize(file, 256*1024)), index: index}
		streams = append(streams, stream)
		if err := stream.decoder.Decode(&stream.record); err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			return fmt.Errorf("decode sort chunk: %w", err)
		}
		heap.Push(&queue, stream)
	}
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		stream := heap.Pop(&queue).(*chunkStream)
		if err := consume(stream.record); err != nil {
			return err
		}
		if err := stream.decoder.Decode(&stream.record); err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			return fmt.Errorf("decode sort chunk: %w", err)
		}
		heap.Push(&queue, stream)
	}
	return nil
}

func newStagingPath(output string) (string, error) {
	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve output directory: %w", err)
	}
	if resolved != filepath.Clean(parent) {
		return "", fmt.Errorf("output directory must not traverse symlinks")
	}
	file, err := os.CreateTemp(parent, "."+filepath.Base(output)+".staging-*")
	if err != nil {
		return "", fmt.Errorf("create staging path: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

func removeSQLiteFiles(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}
