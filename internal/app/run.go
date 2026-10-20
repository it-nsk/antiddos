// Package app assembles the daemon components and manages their lifecycle.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
	"github.com/it-nsk/antiddos/internal/blockmanager"
	"github.com/it-nsk/antiddos/internal/blockpolicy"
	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/configservice"
	"github.com/it-nsk/antiddos/internal/control"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/reader"
	"github.com/it-nsk/antiddos/internal/request"
	"github.com/it-nsk/antiddos/internal/storage"
	"github.com/it-nsk/antiddos/internal/webcontrol"
)

const lineBufferSize = 256

// RunOptions contains command-line choices parsed by cmd/antiddos.
type RunOptions struct {
	Config, LogFile                    string
	ControlSocketPath, WebSocketPath   string
	FromStart, PrintLines, PrintEvents bool
}

func Run(ctx context.Context, opts RunOptions, logger *slog.Logger) error {
	cfg, err := config.LoadWithLogFile(opts.Config, opts.LogFile)
	if err != nil {
		return err
	}
	if opts.FromStart {
		cfg.StartPosition = string(reader.StartAtBeginning)
	}
	rulesBySource := make(map[string][]engine.Rule, len(cfg.LogSources))
	parsersBySource := make(map[string]parser.Parser, len(cfg.LogSources))
	ruleSource := make(map[string]string, len(cfg.Engine.Rules))
	for _, configuredRule := range cfg.Engine.Rules {
		rule := engine.Rule{
			ID: configuredRule.ID, LogSource: configuredRule.LogSource, IgnoreIPs: configuredRule.IgnoreIPs,
			PathRegex: configuredRule.PathRegex,
			Window:    configuredRule.Window, Threshold: configuredRule.Threshold,
			GroupBy: engine.GroupField(configuredRule.GroupBy),
		}
		rulesBySource[configuredRule.LogSource] = append(rulesBySource[configuredRule.LogSource], rule)
		ruleSource[configuredRule.ID] = configuredRule.LogSource
	}
	liveTail := cfg.StartPosition == string(reader.StartAtEnd)
	ruleEngines := make(map[string]*engine.Engine, len(cfg.LogSources))
	var revisions []string
	for _, source := range cfg.LogSources {
		sourceParser, err := parser.New(source.Format, source.LogFormat)
		if err != nil {
			return fmt.Errorf("initialize parser for log source %q: %w", source.ID, err)
		}
		parsersBySource[source.ID] = sourceParser
		ruleEngine, err := engine.NewWithOptions(rulesBySource[source.ID], engine.Options{
			LiveClock: liveTail, IgnoreIPs: cfg.Engine.IgnoreIPs,
		})
		if err != nil {
			return fmt.Errorf("initialize rule engine for log source %q: %w", source.ID, err)
		}
		if liveTail {
			ruleEngine.AdvanceWallClock(time.Now())
		}
		ruleEngines[source.ID] = ruleEngine
		revisions = append(revisions, ruleEngine.RuleRevisions()...)
	}
	blockPolicy, err := blockpolicy.New(cfg.BlockDuration)
	if err != nil {
		return fmt.Errorf("initialize block policy: %w", err)
	}
	var blockAction action.Action = action.DryRun{}
	if cfg.BlockMode == config.BlockModeNFTables {
		blockAction = &action.NFTables{BlockTCPPorts: cfg.BlockTCPPorts}
	}
	analysisConfigID := engine.AnalysisConfigID(revisions)
	database, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("initialize SQLite storage: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			logger.Error("close SQLite storage", "error", err)
		}
	}()
	manager, err := blockmanager.New(blockPolicy, cfg.BlockDuration, blockAction, database)
	if err != nil {
		return err
	}
	if err := manager.Cleanup(ctx, time.Now()); err != nil {
		return fmt.Errorf("prune expired block records: %w", err)
	}
	if cfg.BlockMode == config.BlockModeNFTables {
		if err := manager.Restore(ctx, func(ip netip.Addr, ruleID string) bool {
			source := ruleSource[ruleID]
			if ruleEngine, ok := ruleEngines[source]; ok {
				return ruleEngine.IsIgnoredForRule(ip, ruleID)
			}
			for _, ruleEngine := range ruleEngines {
				if ruleEngine.IsIgnored(request.Event{IP: ip}) {
					return true
				}
			}
			return false
		}, func(result action.Result) {
			logBlockResult(logger, result, false)
		}); err != nil {
			return err
		}
	}
	localErrors := make(chan error, 2)
	localCtx, cancelLocal := context.WithCancel(ctx)
	localServers := 0
	defer func() {
		cancelLocal()
		for range localServers {
			<-localErrors
		}
	}()
	if cfg.BlockMode == config.BlockModeNFTables && opts.ControlSocketPath != "" {
		localServers++
		go func() {
			localErrors <- control.Serve(localCtx, opts.ControlSocketPath, manager)
		}()
	}
	if opts.WebSocketPath != "" {
		webConfig, err := (&configservice.Service{Path: opts.Config}).Read()
		if err != nil {
			return fmt.Errorf("read web configuration revision: %w", err)
		}
		webReader, err := storage.OpenReader(cfg.DatabasePath)
		if err != nil {
			return fmt.Errorf("open web statistics reader: %w", err)
		}
		defer webReader.Close()
		service := &webcontrol.Service{
			Config: &configservice.Service{Path: opts.Config},
			Stats:  webReader,
			Status: webcontrol.Status{ConfigRevision: webConfig.Revision, StartedAt: time.Now(), BlockMode: cfg.BlockMode},
		}
		localServers++
		go func() {
			localErrors <- webcontrol.Serve(localCtx, opts.WebSocketPath, service)
		}()
	}
	followers := make([]*reader.Follower, 0, len(cfg.LogSources))
	for _, source := range cfg.LogSources {
		follower, err := reader.Open(reader.Options{
			Source: source.ID, Path: source.Path,
			StartPosition: reader.StartPosition(cfg.StartPosition),
		}, logger)
		if err != nil {
			for _, opened := range followers {
				opened.Close()
			}
			return err
		}
		followers = append(followers, follower)
	}

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	lines := make(chan reader.Line, lineBufferSize*len(followers))
	readerDone := make(chan error, len(followers))
	for _, follower := range followers {
		go func(follower *reader.Follower) { readerDone <- follower.Run(readerCtx, lines) }(follower)
	}

	logAttributes := []any{
		"database_file", cfg.DatabasePath,
		"start_position", cfg.StartPosition,
		"block_mode", cfg.BlockMode,
		"block_duration", cfg.BlockDuration,
		"block_tcp_ports", cfg.BlockTCPPorts,
		"rules", len(cfg.Engine.Rules),
		"analysis_config_id", analysisConfigID,
	}
	if len(cfg.LogSources) == 1 {
		logAttributes = append([]any{"log_file", cfg.LogSources[0].Path}, logAttributes...)
	} else {
		sources := make(map[string]map[string]string, len(cfg.LogSources))
		for _, source := range cfg.LogSources {
			sources[source.ID] = map[string]string{"path": source.Path, "format": source.Format}
		}
		logAttributes = append([]any{"log_sources", sources}, logAttributes...)
	}
	logger.Info("service started", logAttributes...)
	statistics := runStatistics{}
	metricCollector := metrics.NewCollector()
	metricsTicker := time.NewTicker(metrics.SampleInterval)
	defer metricsTicker.Stop()
	blockCleanupCtx, cancelBlockCleanup := context.WithCancel(ctx)
	blockCleanupDone := make(chan struct{})
	go func() {
		defer close(blockCleanupDone)
		manager.RunCleanup(blockCleanupCtx, time.Minute, func(err error) { logger.Error("prune expired block records", "error", err) })
	}()
	defer func() { cancelBlockCleanup(); <-blockCleanupDone }()
	var expiryTicker *time.Ticker
	var expiryTick <-chan time.Time
	if liveTail {
		expiryTicker = time.NewTicker(time.Second)
		expiryTick = expiryTicker.C
		defer expiryTicker.Stop()
	}
	defer func() {
		logger.Info(
			"service stopped",
			"lines_read", statistics.linesRead,
			"parsed_requests", statistics.parsedRequests,
			"parse_failures", statistics.parseFailures,
			"matching_requests", statistics.matchingRequests,
			"engine_processed_requests", statistics.engineProcessedRequests,
			"evaluated_matching_requests", statistics.evaluatedMatchingRequests,
			"late_events", statistics.lateEvents,
			"late_matching_requests", statistics.lateMatchingRequests,
			"violating_requests", statistics.violatingRequests,
			"violating_evaluations", statistics.violatingEvaluations,
			"emitted_detections", statistics.emittedDetections,
			"threshold_detections", statistics.thresholdDetections,
			"unprocessed_lines", statistics.unprocessedLines,
			"incomplete", statistics.incomplete,
		)
	}()

	processEvent := func(ruleEngine *engine.Engine, event request.Event) (bool, error) {
		if ruleEngine.IsIgnored(event) {
			return ruleEngine.Matches(event), nil
		}
		if ruleEngine.IsLate(event.Timestamp) {
			statistics.lateEvents++
			matched := ruleEngine.Matches(event)
			if matched {
				statistics.lateMatchingRequests++
			}
			if statistics.lateEvents == 1 {
				logger.Warn("late request excluded from rule windows", "timestamp", event.Timestamp)
			}
			return matched, nil
		}

		statistics.engineProcessedRequests++
		evaluations, matched, err := ruleEngine.ProcessWithMatch(event)
		if err != nil {
			return matched, err
		}
		if matched {
			statistics.evaluatedMatchingRequests++
		}
		violating := false
		for _, evaluation := range evaluations {
			if evaluation.Violated {
				violating = true
				statistics.violatingEvaluations++
			}
			if evaluation.Detection == nil {
				continue
			}
			if err := database.RecordDetection(context.Background(), *evaluation.Detection, event); err != nil {
				return matched, fmt.Errorf("persist detection: %w", err)
			}
			statistics.emittedDetections++
			statistics.thresholdDetections++
			logDetection(logger, analysisConfigID, *evaluation.Detection)
			result, err := manager.Process(ctx, *evaluation.Detection, time.Now())
			logBlockResult(logger, result, cfg.BlockMode == config.BlockModeDryRun)
			if err != nil {
				logger.Error("persist active block", "ip", result.IP, "error", err)
			}
		}
		if violating {
			statistics.violatingRequests++
		}
		return matched, nil
	}
	var processingError error
	readersRemaining := len(followers)
readLoop:
	for {
		if readersRemaining == 0 && len(lines) == 0 {
			break
		}
		select {
		case line := <-lines:
			statistics.linesRead++
			if opts.PrintLines {
				fmt.Fprintln(os.Stdout, line.Text)
			}

			sourceParser := parsersBySource[line.Source]
			event, err := sourceParser.Parse(line.Text)
			if err != nil {
				statistics.parseFailures++
				if opts.PrintEvents {
					logger.Warn("request parse failed", "error", err)
				}
				continue
			}
			statistics.parsedRequests++
			ruleEngine := ruleEngines[line.Source]
			if opts.PrintEvents {
				logRequestEvent(logger, event)
			}
			matches, err := processEvent(ruleEngine, event)
			if matches {
				statistics.matchingRequests++
			}
			metricCollector.Add(line.Source, event, matches)
			if err != nil {
				processingError = fmt.Errorf("process request: %w", err)
				break readLoop
			}
		case <-metricsTicker.C:
			if err := metricCollector.Flush(context.Background(), database); err != nil {
				processingError = fmt.Errorf("persist traffic statistics: %w", err)
				break readLoop
			}
		case now := <-expiryTick:
			for _, ruleEngine := range ruleEngines {
				ruleEngine.AdvanceWallClock(now)
			}
		case readerErr := <-readerDone:
			readersRemaining--
			if readerErr != nil && processingError == nil {
				processingError = readerErr
				statistics.incomplete = true
				cancelReader()
			}
		case serverErr := <-localErrors:
			localServers--
			if serverErr != nil {
				processingError = fmt.Errorf("local API socket: %w", serverErr)
				break readLoop
			}
		}
	}

	if processingError != nil {
		statistics.incomplete = true
		cancelReader()
		for readersRemaining > 0 {
			select {
			case <-readerDone:
				readersRemaining--
			case <-lines:
				statistics.unprocessedLines++
			}
		}
		for len(lines) > 0 {
			<-lines
			statistics.unprocessedLines++
		}
	}
	if err := metricCollector.Flush(context.Background(), database); err != nil {
		statistics.incomplete = true
		if processingError == nil {
			processingError = fmt.Errorf("persist final traffic statistics: %w", err)
		} else {
			logger.Error("persist final traffic statistics", "error", err)
		}
	}
	for _, ruleEngine := range ruleEngines {
		ruleEngine.Cleanup()
	}
	if processingError != nil {
		return processingError
	}
	if statistics.lateEvents > 0 {
		logger.Warn("analysis excluded late requests", "late_events", statistics.lateEvents, "late_matching_requests", statistics.lateMatchingRequests)
	}
	return nil
}

func logBlockResult(logger *slog.Logger, result action.Result, dryRun bool) {
	attributes := []any{"status", result.Status, "ip", result.IP, "reason", result.Reason, "dry_run", dryRun}
	if !result.ExpiresAt.IsZero() {
		attributes = append(attributes, "expires_at", result.ExpiresAt)
	}
	if result.Err != nil {
		attributes = append(attributes, "error", result.Err)
		logger.Error("block action result", attributes...)
		return
	}
	logger.Info("block action result", attributes...)
}

type runStatistics struct {
	linesRead                 uint64
	parsedRequests            uint64
	parseFailures             uint64
	matchingRequests          uint64
	engineProcessedRequests   uint64
	evaluatedMatchingRequests uint64
	lateEvents                uint64
	lateMatchingRequests      uint64
	violatingRequests         uint64
	violatingEvaluations      uint64
	emittedDetections         uint64
	thresholdDetections       uint64
	unprocessedLines          uint64
	incomplete                bool
}

func logRequestEvent(logger *slog.Logger, event request.Event) {
	responseBytes := any("-")
	if event.ResponseBytes != nil {
		responseBytes = *event.ResponseBytes
	}

	logger.Info(
		"request parsed",
		"timestamp", event.Timestamp,
		"ip", event.IP,
		"method", event.Method,
		"path", event.Path,
		"raw_query", event.RawQuery,
		"status", event.Status,
		"response_bytes", responseBytes,
		"user_agent", event.UserAgent,
	)
}

func logDetection(logger *slog.Logger, analysisConfigID string, detection engine.Detection) {
	logger.Warn(
		"request pattern detected",
		"rule", detection.RuleID,
		"rule_revision", detection.RuleRevision,
		"analysis_config_id", analysisConfigID,
		"group_by", detection.GroupField,
		"group_value", detection.GroupValue,
		"group", detection.GroupKey,
		"event_timestamp", detection.EventTimestamp,
		"emitted_at", time.Now(),
		"count", detection.Count,
		"window", detection.Window,
		"threshold", detection.Threshold,
		"dry_run", detection.DryRun,
	)
}
