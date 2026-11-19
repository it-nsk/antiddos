package webui

// This file owns historical imports started from the browser.  It deliberately
// lives in the unprivileged web process: its only filesystem authority is the
// explicit roots and output directory passed at startup.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/history"
)

type HistoryJobRequest struct {
	SourceID       string `json:"source_id"`
	Directory      string `json:"directory"`
	NameRegex      string `json:"name_regex"`
	Order          string `json:"order"`
	Timezone       string `json:"timezone,omitempty"`
	SyslogYear     int    `json:"syslog_year,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	AllowMalformed int64  `json:"allow_malformed,omitempty"`
	Publish        bool   `json:"publish,omitempty"`
	ComparisonRule string `json:"comparison_rule,omitempty"`
	ParentImportID string `json:"parent_import_id,omitempty"`
}

type HistoryJob struct {
	ID            string                 `json:"id"`
	State         string                 `json:"state"`
	CreatedAt     time.Time              `json:"created_at"`
	StartedAt     *time.Time             `json:"started_at,omitempty"`
	FinishedAt    *time.Time             `json:"finished_at,omitempty"`
	Request       HistoryJobRequest      `json:"request"`
	Progress      history.ImportProgress `json:"progress"`
	Result        *history.ImportResult  `json:"result,omitempty"`
	Error         string                 `json:"error,omitempty"`
	OutputPath    string                 `json:"output_path"`
	LivePublished bool                   `json:"live_published"`
}

// HistoryPreview deliberately exposes only base file names and aggregate
// parser diagnostics; archive contents never cross the browser API.
type HistoryPreviewFile struct {
	Name            string    `json:"name"`
	Size            int64     `json:"size"`
	Compressed      bool      `json:"compressed"`
	Lines           int64     `json:"lines"`
	Parsed          int64     `json:"parsed"`
	Ignored         int64     `json:"ignored"`
	Malformed       int64     `json:"malformed"`
	OutOfOrderLines int64     `json:"out_of_order_lines"`
	FirstEvent      time.Time `json:"first_event,omitempty"`
	LastEvent       time.Time `json:"last_event,omitempty"`
	Error           string    `json:"error,omitempty"`
}
type HistoryPreview struct {
	Files                []HistoryPreviewFile `json:"files"`
	Lines                int64                `json:"lines"`
	Parsed               int64                `json:"parsed"`
	Ignored              int64                `json:"ignored"`
	Malformed            int64                `json:"malformed"`
	Overlapping          int                  `json:"overlapping"`
	ExpandedBytes        int64                `json:"expanded_bytes"`
	FirstEvent           time.Time            `json:"first_event,omitempty"`
	LastEvent            time.Time            `json:"last_event,omitempty"`
	WorkDir              string               `json:"work_dir"`
	OutputDir            string               `json:"output_dir"`
	EstimatedBytes       int64                `json:"estimated_bytes"`
	WorkAvailableBytes   int64                `json:"work_available_bytes"`
	OutputAvailableBytes int64                `json:"output_available_bytes"`
}

type historyJobs struct {
	configPath, outputDir, workDir string
	roots                          []string
	publishAllowed                 bool
	nice, ioPriority               int
	mu                             sync.RWMutex
	jobs                           map[string]*HistoryJob
	cancel                         map[string]context.CancelFunc
}

const historyJobsStateFile = "history-jobs.json"

func newHistoryJobs(configPath, outputDir string, roots []string, publish ...bool) (*historyJobs, error) {
	if configPath == "" && outputDir == "" && len(roots) == 0 {
		return nil, nil
	}
	if configPath == "" || outputDir == "" || len(roots) == 0 {
		return nil, fmt.Errorf("managed history requires history config, output directory, and at least one history root")
	}
	if !filepath.IsAbs(configPath) || !filepath.IsAbs(outputDir) {
		return nil, fmt.Errorf("history config, output directory, and roots must be absolute")
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("create history output directory: %w", err)
	}
	cleanOutput := filepath.Clean(outputDir)
	resolvedOutput, err := filepath.EvalSymlinks(cleanOutput)
	if err != nil {
		return nil, fmt.Errorf("resolve history output directory: %w", err)
	}
	if resolvedOutput != cleanOutput {
		return nil, fmt.Errorf("history output directory must not traverse symlinks")
	}
	publishAllowed := len(publish) > 0 && publish[0]
	workDir := cleanOutput
	if !filepath.IsAbs(workDir) {
		return nil, fmt.Errorf("history work directory must be absolute")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	resolvedWork, err := filepath.EvalSymlinks(workDir)
	if err != nil || resolvedWork != workDir {
		return nil, fmt.Errorf("history work directory must not traverse symlinks: %v", err)
	}
	m := &historyJobs{configPath: configPath, outputDir: cleanOutput, workDir: workDir, roots: append([]string(nil), roots...), publishAllowed: publishAllowed, jobs: map[string]*HistoryJob{}, cancel: map[string]context.CancelFunc{}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *historyJobs) statePath() string { return filepath.Join(m.outputDir, historyJobsStateFile) }

func (m *historyJobs) load() error {
	data, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read historical job state: %w", err)
	}
	var jobs []HistoryJob
	if err := json.Unmarshal(data, &jobs); err != nil {
		return fmt.Errorf("decode historical job state: %w", err)
	}
	changed := false
	for i := range jobs {
		job := jobs[i]
		if !validHistoryJobID(job.ID) || expectedHistoryOutputPath(m.outputDir, job.ID) != job.OutputPath || history.ValidateAllowedDirectory(job.Request.Directory, m.roots) != nil {
			continue
		}
		if job.State == "queued" || job.State == "running" {
			now := time.Now().UTC()
			job.State = "interrupted"
			job.Error = "web process restarted; import was not published"
			job.FinishedAt = &now
			changed = true
		}
		m.jobs[job.ID] = &job
	}
	if changed {
		return m.persistLocked()
	}
	return nil
}

func expectedHistoryOutputPath(outputDir, id string) string {
	return filepath.Join(outputDir, "history-"+id+".sqlite")
}

func validHistoryJobID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 12
}

// persistLocked writes state before the user can observe a state transition.
// Rename makes every completed write atomic; the SQLite result itself remains
// independently atomically published by history.Import.
func (m *historyJobs) persistLocked() error {
	jobs := make([]HistoryJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		jobs = append(jobs, *job)
	}
	data, err := json.Marshal(jobs)
	if err != nil {
		return fmt.Errorf("encode historical job state: %w", err)
	}
	temp, err := os.CreateTemp(m.outputDir, ".history-jobs-")
	if err != nil {
		return fmt.Errorf("create historical job state: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write historical job state: %w", err)
	}
	if err := os.Rename(tempName, m.statePath()); err != nil {
		return fmt.Errorf("publish historical job state: %w", err)
	}
	if directory, err := os.Open(m.outputDir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (m *historyJobs) list() []HistoryJob {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]HistoryJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		result = append(result, *job)
	}
	return result
}
func (m *historyJobs) get(id string) (HistoryJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	if !ok {
		return HistoryJob{}, false
	}
	return *job, true
}

func (m *historyJobs) start(request HistoryJobRequest) (HistoryJob, error) {
	if request.SourceID == "" || request.Directory == "" || request.NameRegex == "" {
		return HistoryJob{}, fmt.Errorf("source_id, directory, and name_regex are required")
	}
	if request.Order == "" {
		request.Order = history.OrderNatural
	}
	if request.From == "" != (request.To == "") {
		return HistoryJob{}, fmt.Errorf("from and to must be supplied together")
	}
	if request.AllowMalformed < 0 {
		return HistoryJob{}, fmt.Errorf("allow_malformed must not be negative")
	}
	if request.Publish {
		return HistoryJob{}, fmt.Errorf("publish is a separate explicit action after import")
	}
	if err := history.ValidateAllowedDirectory(request.Directory, m.roots); err != nil {
		return HistoryJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.jobs {
		if existing.State == "queued" || existing.State == "running" {
			return HistoryJob{}, fmt.Errorf("a historical job is already active")
		}
	}
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return HistoryJob{}, err
	}
	id := hex.EncodeToString(bytes)
	now := time.Now().UTC()
	job := &HistoryJob{ID: id, State: "queued", CreatedAt: now, Request: request, OutputPath: expectedHistoryOutputPath(m.outputDir, id)}
	m.jobs[id] = job
	if err := m.persistLocked(); err != nil {
		delete(m.jobs, id)
		return HistoryJob{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel[id] = cancel
	go m.run(ctx, id)
	return *job, nil
}

func (m *historyJobs) rewriteRule(ruleID string) (HistoryJob, error) {
	if ruleID == "" {
		return HistoryJob{}, fmt.Errorf("rule ID is required")
	}
	cfg, err := config.Load(m.configPath)
	if err != nil {
		return HistoryJob{}, err
	}
	var sourceID string
	for _, rule := range cfg.Engine.Rules {
		if rule.ID == ruleID {
			sourceID = rule.LogSource
			break
		}
	}
	if sourceID == "" {
		return HistoryJob{}, fmt.Errorf("configured rule %q not found", ruleID)
	}
	m.mu.RLock()
	var latest *HistoryJob
	for _, job := range m.jobs {
		if job.State == "published" && job.Result != nil && job.Request.SourceID == sourceID && job.Request.ComparisonRule == "" && (latest == nil || job.CreatedAt.After(latest.CreatedAt)) {
			copy := *job
			latest = &copy
		}
	}
	m.mu.RUnlock()
	if latest == nil {
		return HistoryJob{}, fmt.Errorf("no completed archive job for rule source %q", sourceID)
	}
	request := latest.Request
	request.ComparisonRule, request.ParentImportID, request.Publish = ruleID, latest.Result.ImportID, false
	return m.start(request)
}

func (m *historyJobs) preview(ctx context.Context, request HistoryJobRequest) (HistoryPreview, error) {
	if request.SourceID == "" || request.Directory == "" || request.NameRegex == "" {
		return HistoryPreview{}, fmt.Errorf("source_id, directory, and name_regex are required")
	}
	if request.Order == "" {
		request.Order = history.OrderNatural
	}
	if err := history.ValidateAllowedDirectory(request.Directory, m.roots); err != nil {
		return HistoryPreview{}, err
	}
	cfg, err := config.Load(m.configPath)
	if err != nil {
		return HistoryPreview{}, err
	}
	var source *config.LogSourceConfig
	for i := range cfg.LogSources {
		if cfg.LogSources[i].ID == request.SourceID {
			source = &cfg.LogSources[i]
			break
		}
	}
	if source == nil {
		return HistoryPreview{}, fmt.Errorf("configured log source %q not found", request.SourceID)
	}
	var location *time.Location
	if request.Timezone != "" {
		location, err = time.LoadLocation(request.Timezone)
		if err != nil {
			return HistoryPreview{}, fmt.Errorf("load timezone: %w", err)
		}
	}
	report, err := history.Preview(ctx, history.PreviewOptions{Directory: request.Directory, AllowedRoots: m.roots, NameRegex: request.NameRegex, Format: source.Format, LogFormat: source.LogFormat, Order: request.Order, Location: location, SyslogYear: request.SyslogYear, MaxFiles: 1000, MaxInputBytes: 100 << 30, MaxExpandedBytes: 200 << 30, MaxLineBytes: 1 << 20})
	if err != nil {
		return HistoryPreview{}, err
	}
	estimate := report.ExpandedBytes * 4
	if estimate < 256<<20 {
		estimate = 256 << 20
	}
	result := HistoryPreview{Lines: report.Lines, Parsed: report.Parsed, Ignored: report.Ignored, Malformed: report.Malformed, Overlapping: report.Overlapping, ExpandedBytes: report.ExpandedBytes, WorkDir: m.workDir, OutputDir: m.outputDir, EstimatedBytes: estimate, Files: make([]HistoryPreviewFile, 0, len(report.Files))}
	var workStat, outputStat syscall.Statfs_t
	if err := syscall.Statfs(m.workDir, &workStat); err != nil {
		return HistoryPreview{}, err
	}
	if err := syscall.Statfs(m.outputDir, &outputStat); err != nil {
		return HistoryPreview{}, err
	}
	result.WorkAvailableBytes = int64(workStat.Bavail) * int64(workStat.Bsize)
	result.OutputAvailableBytes = int64(outputStat.Bavail) * int64(outputStat.Bsize)
	for _, file := range report.Files {
		item := HistoryPreviewFile{Name: path.Base(file.Path), Size: file.Size, Compressed: file.Compressed, Lines: file.Lines, Parsed: file.Parsed, Ignored: file.Ignored, Malformed: file.Malformed, OutOfOrderLines: file.OutOfOrderLines, FirstEvent: file.FirstEvent, LastEvent: file.LastEvent}
		if file.Err != nil {
			item.Error = file.Err.Error()
		}
		result.Files = append(result.Files, item)
		if !file.FirstEvent.IsZero() && (result.FirstEvent.IsZero() || file.FirstEvent.Before(result.FirstEvent)) {
			result.FirstEvent = file.FirstEvent
		}
		if !file.LastEvent.IsZero() && (result.LastEvent.IsZero() || file.LastEvent.After(result.LastEvent)) {
			result.LastEvent = file.LastEvent
		}
	}
	return result, nil
}
func (m *historyJobs) stop(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cancel, ok := m.cancel[id]
	if ok {
		cancel()
		_ = m.persistLocked()
	}
	return ok
}
func (m *historyJobs) publish(ctx context.Context, id string) (HistoryJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.publishAllowed {
		return HistoryJob{}, fmt.Errorf("historical live publication is disabled by the web service")
	}
	job := m.jobs[id]
	if job == nil || job.State != "published" || job.Result == nil {
		return HistoryJob{}, fmt.Errorf("completed historical result not found")
	}
	if job.Request.ComparisonRule != "" {
		return HistoryJob{}, fmt.Errorf("comparison results cannot be published to the live database")
	}
	if job.LivePublished {
		return *job, nil
	}
	cfg, err := config.Load(m.configPath)
	if err != nil {
		return HistoryJob{}, err
	}
	if _, err := history.PublishToDatabase(ctx, job.OutputPath, cfg.DatabasePath, job.Result.ImportID); err != nil {
		return HistoryJob{}, err
	}
	job.LivePublished = true
	if err := m.persistLocked(); err != nil {
		return HistoryJob{}, err
	}
	return *job, nil
}

func (m *historyJobs) publishResult(ctx context.Context, name, importID string) (history.PublishResult, error) {
	if !m.publishAllowed {
		return history.PublishResult{}, fmt.Errorf("historical live publication is disabled by the web service")
	}
	if name == "" || filepath.Base(name) != name || filepath.Ext(name) != ".sqlite" || importID == "" {
		return history.PublishResult{}, fmt.Errorf("result filename and import ID are required")
	}
	resultPath := filepath.Join(m.outputDir, name)
	info, err := os.Lstat(resultPath)
	if err != nil {
		return history.PublishResult{}, err
	}
	if !info.Mode().IsRegular() {
		return history.PublishResult{}, fmt.Errorf("result must be a regular SQLite file")
	}
	cfg, err := config.Load(m.configPath)
	if err != nil {
		return history.PublishResult{}, err
	}
	return history.PublishToDatabase(ctx, resultPath, cfg.DatabasePath, importID)
}
func (m *historyJobs) run(ctx context.Context, id string) {
	m.mu.Lock()
	job := m.jobs[id]
	now := time.Now().UTC()
	job.State = "running"
	job.StartedAt = &now
	request := job.Request
	output := job.OutputPath
	if err := m.persistLocked(); err != nil {
		job.State = "failed"
		job.Error = err.Error()
		finished := time.Now().UTC()
		job.FinishedAt = &finished
		cancel := m.cancel[id]
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	m.mu.Unlock()
	err := applyHistoryPriority(m.nice, m.ioPriority)
	var cfg config.Config
	if err == nil {
		cfg, err = config.Load(m.configPath)
	}
	var location *time.Location
	if err == nil && request.Timezone != "" {
		location, err = time.LoadLocation(request.Timezone)
	}
	var from, to time.Time
	if err == nil && request.From != "" {
		from, err = time.Parse(time.RFC3339, request.From)
		if err == nil {
			to, err = time.Parse(time.RFC3339, request.To)
		}
		if err == nil && !from.Before(to) {
			err = fmt.Errorf("from must be before to")
		}
	}
	var result history.ImportResult
	if err == nil {
		if request.ComparisonRule != "" {
			selected := cfg.Engine.Rules[:0]
			for _, rule := range cfg.Engine.Rules {
				if rule.ID == request.ComparisonRule && rule.LogSource == request.SourceID {
					selected = append(selected, rule)
				}
			}
			if len(selected) != 1 {
				err = fmt.Errorf("comparison rule %q is unavailable for source %q", request.ComparisonRule, request.SourceID)
			} else {
				cfg.Engine.Rules = selected
			}
		}
	}
	if err == nil {
		preview, previewErr := m.preview(ctx, request)
		if previewErr != nil {
			err = previewErr
		}
		if err == nil {
			result, err = history.Import(ctx, history.ImportOptions{Config: cfg, SourceID: request.SourceID, Directory: request.Directory, AllowedRoots: m.roots, NameRegex: request.NameRegex, OutputPath: output, Order: request.Order, Location: location, SyslogYear: request.SyslogYear, MaxFiles: 1000, MaxInputBytes: 100 << 30, MaxExpandedBytes: 200 << 30, MaxLineBytes: 1 << 20, SortMemoryBytes: 256 << 20, MaxSortBytes: preview.EstimatedBytes, PreflightBytes: preview.EstimatedBytes, TempDirectory: m.workDir, AllowMalformed: request.AllowMalformed, From: from, To: to, ComparisonRule: request.ComparisonRule, ParentImportID: request.ParentImportID, Progress: func(progress history.ImportProgress) {
				m.mu.Lock()
				if current := m.jobs[id]; current != nil {
					current.Progress = progress
					if err := m.persistLocked(); err != nil {
						if cancel := m.cancel[id]; cancel != nil {
							cancel()
						}
					}
				}
				m.mu.Unlock()
			}})
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job = m.jobs[id]
	finished := time.Now().UTC()
	job.FinishedAt = &finished
	delete(m.cancel, id)
	if err != nil {
		if ctx.Err() != nil {
			job.State = "cancelled"
			job.Error = "cancelled"
		} else {
			job.State = "failed"
			job.Error = err.Error()
		}
		_ = m.persistLocked()
		return
	}
	job.State = "published"
	job.Result = &result
	job.LivePublished = false
	_ = m.persistLocked()
}
