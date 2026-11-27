// Package history provides read-only inspection of archived log files. It is
// deliberately independent from the live follower, storage, and action path.
package history

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/parser"
)

const (
	OrderNatural      = "natural"
	OrderLexical      = "lexical"
	OrderFirstEvent   = "first-event"
	OrderFilenameTime = "filename-time"
)

type PreviewOptions struct {
	Directory string
	// AllowedRoots limits Directory to pre-authorized physical directories. An
	// empty list is retained for the local CLI; callers accepting untrusted
	// directory input (the web job service) must provide roots.
	AllowedRoots       []string
	NameRegex          string
	Format             string
	LogFormat          string
	Order              string
	FilenameTimeRegex  string
	FilenameTimeLayout string
	Location           *time.Location
	SyslogYear         int
	MaxFiles           int
	MaxInputBytes      int64
	MaxExpandedBytes   int64
	MaxLineBytes       int
}

type FileReport struct {
	Path       string
	Size       int64
	Compressed bool
	Lines      int64
	Parsed     int64
	Ignored    int64
	Malformed  int64
	// Unparsed is retained as the sum of Ignored and Malformed for callers
	// compiled against the first preview contract.
	Unparsed        int64
	FirstEvent      time.Time
	LastEvent       time.Time
	OutOfOrderLines int64
	Err             error
}

type Report struct {
	Files          []FileReport
	TotalSize      int64
	Lines          int64
	Parsed         int64
	Ignored        int64
	Malformed      int64
	Unparsed       int64
	Overlapping    int
	ExpandedBytes  int64
	NameMatchScope string
}

type candidate struct {
	path         string
	name         string
	size         int64
	info         os.FileInfo
	compressed   bool
	rotation     int
	hasRotate    bool
	filenameTime time.Time
	liveSnapshot *os.File
}

var unsupportedArchiveRE = regexp.MustCompile(`(?i)\.(?:zip|bz2|xz|zst|7z|rar)$`)

func Preview(ctx context.Context, options PreviewOptions) (Report, error) {
	if err := validateOptions(options); err != nil {
		return Report{}, err
	}
	logParser, err := parser.NewHistorical(options.Format, options.LogFormat, parser.HistoricalOptions{
		Location: options.Location, SyslogYear: options.SyslogYear,
	})
	if err != nil {
		return Report{}, fmt.Errorf("configure historical parser: %w", err)
	}
	files, totalSize, err := discover(options)
	if err != nil {
		return Report{}, err
	}
	report := Report{TotalSize: totalSize, NameMatchScope: "base filename (not the path)"}
	remainingExpanded := options.MaxExpandedBytes
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		fileOptions := options
		fileOptions.MaxExpandedBytes = remainingExpanded
		fileReport, expanded := inspectFile(ctx, file, logParser, fileOptions)
		report.Files = append(report.Files, fileReport)
		report.ExpandedBytes += expanded
		remainingExpanded -= min(expanded, remainingExpanded)
		report.Lines += fileReport.Lines
		report.Parsed += fileReport.Parsed
		report.Ignored += fileReport.Ignored
		report.Malformed += fileReport.Malformed
		report.Unparsed += fileReport.Unparsed
	}
	if options.Order == OrderFirstEvent {
		sort.SliceStable(report.Files, func(i, j int) bool {
			left, right := report.Files[i], report.Files[j]
			// Files with no recognized event are retained for diagnostics and
			// follow timestamped files in deterministic filename order.
			if left.FirstEvent.IsZero() != right.FirstEvent.IsZero() {
				return !left.FirstEvent.IsZero()
			}
			if !left.FirstEvent.Equal(right.FirstEvent) {
				return left.FirstEvent.Before(right.FirstEvent)
			}
			return left.Path < right.Path
		})
	}
	for index := 1; index < len(report.Files); index++ {
		previous, current := report.Files[index-1], report.Files[index]
		if previous.Err == nil && current.Err == nil && !previous.LastEvent.IsZero() && !current.FirstEvent.IsZero() && !previous.LastEvent.Before(current.FirstEvent) {
			report.Overlapping++
		}
	}
	return report, nil
}

func validateOptions(options PreviewOptions) error {
	if !filepath.IsAbs(options.Directory) {
		return fmt.Errorf("directory must be an absolute path")
	}
	if err := validateAllowedDirectory(options.Directory, options.AllowedRoots); err != nil {
		return err
	}
	if options.NameRegex == "" {
		return fmt.Errorf("name regex must not be empty")
	}
	if options.Order != OrderNatural && options.Order != OrderLexical && options.Order != OrderFirstEvent && options.Order != OrderFilenameTime {
		return fmt.Errorf("order must be %q, %q, %q, or %q", OrderNatural, OrderLexical, OrderFirstEvent, OrderFilenameTime)
	}
	if options.Order == OrderFilenameTime && (options.FilenameTimeRegex == "" || options.FilenameTimeLayout == "") {
		return fmt.Errorf("filename-time order requires filename time regex and layout")
	}
	if options.MaxFiles < 1 || options.MaxInputBytes < 1 || options.MaxExpandedBytes < 1 || options.MaxLineBytes < 1 {
		return fmt.Errorf("all resource limits must be positive")
	}
	return nil
}

func validateAllowedDirectory(directory string, roots []string) error {
	if len(roots) == 0 {
		return nil
	}
	cleanDirectory := filepath.Clean(directory)
	resolvedDirectory, err := filepath.EvalSymlinks(cleanDirectory)
	if err != nil {
		return fmt.Errorf("resolve directory: %w", err)
	}
	if resolvedDirectory != cleanDirectory {
		return fmt.Errorf("directory path must not traverse symlinks: %q resolves to %q", cleanDirectory, resolvedDirectory)
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			return fmt.Errorf("allowed history root must be absolute: %q", root)
		}
		cleanRoot := filepath.Clean(root)
		resolvedRoot, rootErr := filepath.EvalSymlinks(cleanRoot)
		if rootErr != nil {
			return fmt.Errorf("resolve allowed history root %q: %w", root, rootErr)
		}
		if resolvedRoot != cleanRoot {
			return fmt.Errorf("allowed history root must not traverse symlinks: %q", root)
		}
		relative, relErr := filepath.Rel(cleanRoot, cleanDirectory)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("directory %q is outside the configured history roots", directory)
}

// ValidateAllowedDirectory validates the privilege boundary used by a caller
// that receives a directory from an untrusted request. It is intentionally
// separate from discovery so a web handler can reject bad jobs synchronously.
func ValidateAllowedDirectory(directory string, roots []string) error {
	if !filepath.IsAbs(directory) {
		return fmt.Errorf("directory must be an absolute path")
	}
	if len(roots) == 0 {
		return fmt.Errorf("at least one allowed history root is required")
	}
	return validateAllowedDirectory(directory, roots)
}

func discover(options PreviewOptions) ([]candidate, int64, error) {
	pattern, err := regexp.Compile(options.NameRegex)
	if err != nil {
		return nil, 0, fmt.Errorf("compile filename regex: %w", err)
	}
	var filenameTimePattern *regexp.Regexp
	if options.Order == OrderFilenameTime {
		filenameTimePattern, err = regexp.Compile(options.FilenameTimeRegex)
		if err != nil {
			return nil, 0, fmt.Errorf("compile filename time regex: %w", err)
		}
		if filenameTimePattern.NumSubexp() != 1 {
			return nil, 0, fmt.Errorf("filename time regex must contain exactly one capturing group for the timestamp")
		}
	}
	cleanDirectory := filepath.Clean(options.Directory)
	resolvedDirectory, err := filepath.EvalSymlinks(cleanDirectory)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve directory: %w", err)
	}
	if resolvedDirectory != cleanDirectory {
		return nil, 0, fmt.Errorf("directory path must not traverse symlinks: %q resolves to %q", cleanDirectory, resolvedDirectory)
	}
	directory, err := os.Open(cleanDirectory)
	if err != nil {
		return nil, 0, fmt.Errorf("open directory: %w", err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, 0, fmt.Errorf("%q is not a directory", options.Directory)
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, 0, fmt.Errorf("read directory: %w", err)
	}
	files := make([]candidate, 0)
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if !pattern.MatchString(name) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, 0, fmt.Errorf("matched file %q is a symlink; symlinks are not allowed", name)
		}
		if unsupportedArchiveRE.MatchString(name) {
			return nil, 0, fmt.Errorf("matched file %q uses an unsupported archive format; extract ZIP or use plain text/gzip", name)
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return nil, 0, fmt.Errorf("stat matched file %q: %w", name, err)
		}
		if !entryInfo.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("matched path %q is not a regular file", name)
		}
		if entryInfo.Size() > options.MaxInputBytes-total {
			return nil, 0, fmt.Errorf("matched files exceed input size limit of %d bytes", options.MaxInputBytes)
		}
		total += entryInfo.Size()
		rotation, hasRotation := rotationNumber(name)
		var filenameTime time.Time
		if filenameTimePattern != nil {
			match := filenameTimePattern.FindStringSubmatch(name)
			if match == nil {
				return nil, 0, fmt.Errorf("matched file %q does not match filename time regex", name)
			}
			location := options.Location
			if location == nil {
				location = time.UTC
			}
			filenameTime, err = time.ParseInLocation(options.FilenameTimeLayout, match[1], location)
			if err != nil {
				return nil, 0, fmt.Errorf("parse filename timestamp %q in %q: %w", match[1], name, err)
			}
		}
		files = append(files, candidate{
			path: filepath.Join(cleanDirectory, name), name: name, size: entryInfo.Size(), info: entryInfo,
			compressed: strings.HasSuffix(strings.ToLower(name), ".gz"), rotation: rotation, hasRotate: hasRotation, filenameTime: filenameTime,
		})
		if len(files) > options.MaxFiles {
			return nil, 0, fmt.Errorf("matched files exceed limit of %d", options.MaxFiles)
		}
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no regular files matched the filename regex in %q", options.Directory)
	}
	if options.Order == OrderLexical || options.Order == OrderFirstEvent {
		sort.SliceStable(files, func(i, j int) bool { return files[i].name < files[j].name })
	} else if options.Order == OrderFilenameTime {
		sort.SliceStable(files, func(i, j int) bool {
			if !files[i].filenameTime.Equal(files[j].filenameTime) {
				return files[i].filenameTime.Before(files[j].filenameTime)
			}
			return files[i].name < files[j].name
		})
	} else {
		sort.SliceStable(files, func(i, j int) bool {
			left, right := files[i], files[j]
			if left.hasRotate != right.hasRotate {
				return left.hasRotate
			}
			if left.hasRotate && left.rotation != right.rotation {
				return left.rotation > right.rotation
			}
			return left.name < right.name
		})
	}
	return files, total, nil
}

func rotationNumber(name string) (int, bool) {
	withoutGzip := strings.TrimSuffix(strings.ToLower(name), ".gz")
	dot := strings.LastIndexByte(withoutGzip, '.')
	if dot < 0 || dot == len(withoutGzip)-1 {
		return 0, false
	}
	rotation, err := strconv.Atoi(withoutGzip[dot+1:])
	return rotation, err == nil
}

func inspectFile(ctx context.Context, file candidate, logParser parser.Parser, options PreviewOptions) (FileReport, int64) {
	report := FileReport{Path: file.path, Size: file.size, Compressed: file.compressed}
	opened, err := os.Open(file.path)
	if err != nil {
		report.Err = err
		return report, 0
	}
	defer opened.Close()
	openedInfo, err := opened.Stat()
	if err != nil {
		report.Err = err
		return report, 0
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(file.info, openedInfo) || openedInfo.Size() != file.size || !openedInfo.ModTime().Equal(file.info.ModTime()) {
		report.Err = fmt.Errorf("file changed after discovery")
		return report, 0
	}

	var source io.Reader = opened
	var compressed *gzip.Reader
	if file.compressed {
		compressed, err = gzip.NewReader(opened)
		if err != nil {
			report.Err = fmt.Errorf("open gzip: %w", err)
			return report, 0
		}
		defer compressed.Close()
		source = compressed
	}
	limited := &io.LimitedReader{R: source, N: options.MaxExpandedBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, min(options.MaxLineBytes, 64*1024)), options.MaxLineBytes)
	var previous time.Time
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			report.Err = err
			break
		}
		report.Lines++
		event, parseErr := logParser.Parse(scanner.Text())
		if parseErr != nil {
			if parser.IsIgnored(parseErr) {
				report.Ignored++
			} else {
				report.Malformed++
			}
			report.Unparsed++
			continue
		}
		report.Parsed++
		if report.FirstEvent.IsZero() || event.Timestamp.Before(report.FirstEvent) {
			report.FirstEvent = event.Timestamp
		}
		if !previous.IsZero() && event.Timestamp.Before(previous) {
			report.OutOfOrderLines++
		}
		previous = event.Timestamp
		if report.LastEvent.IsZero() || event.Timestamp.After(report.LastEvent) {
			report.LastEvent = event.Timestamp
		}
	}
	expanded := options.MaxExpandedBytes + 1 - limited.N
	if report.Err == nil {
		switch {
		case limited.N <= 0:
			report.Err = fmt.Errorf("expanded data exceeds limit of %d bytes", options.MaxExpandedBytes)
		case scanner.Err() != nil:
			report.Err = fmt.Errorf("read log (the line limit is %d bytes): %w", options.MaxLineBytes, scanner.Err())
		}
	}
	if finalInfo, statErr := opened.Stat(); report.Err == nil && (statErr != nil || finalInfo.Size() != openedInfo.Size() || !finalInfo.ModTime().Equal(openedInfo.ModTime())) {
		report.Err = fmt.Errorf("file changed while it was being read")
	}
	return report, expanded
}
