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
	"github.com/it-nsk/antiddos/internal/control"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/reader"
	"github.com/it-nsk/antiddos/internal/request"
	"github.com/it-nsk/antiddos/internal/storage"
)

const lineBufferSize = 256

// RunOptions contains command-line choices parsed by cmd/antiddos.
type RunOptions struct {
	Config, LogFile                    string
	ControlSocketPath                  string
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
	rules := make([]engine.Rule, len(cfg.Engine.Rules))
	for ruleIndex, configuredRule := range cfg.Engine.Rules {
		rules[ruleIndex] = engine.Rule{
			ID: configuredRule.ID, PathRegex: configuredRule.PathRegex,
			Window: configuredRule.Window, Threshold: configuredRule.Threshold,
			GroupBy: engine.GroupField(configuredRule.GroupBy),
		}
	}
	liveTail := cfg.StartPosition == string(reader.StartAtEnd)
	ruleEngine, err := engine.NewWithOptions(rules, engine.Options{
		LiveClock: liveTail,
		IgnoreIPs: cfg.Engine.IgnoreIPs,
	})
	if err != nil {
		return fmt.Errorf("initialize rule engine: %w", err)
	}
	if liveTail {
		ruleEngine.AdvanceWallClock(time.Now())
	}
	blockPolicy, err := blockpolicy.New(cfg.BlockDuration)
	if err != nil {
		return fmt.Errorf("initialize block policy: %w", err)
	}
	var blockAction action.Action = action.DryRun{}
	if cfg.BlockMode == config.BlockModeNFTables {
		blockAction = &action.NFTables{BlockTCPPorts: cfg.BlockTCPPorts}
	}
	analysisConfigID := engine.AnalysisConfigID(ruleEngine.RuleRevisions())
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
		if err := manager.Restore(ctx, func(ip netip.Addr) bool { return ruleEngine.IsIgnored(request.Event{IP: ip}) }, func(result action.Result) {
			logBlockResult(logger, result, false)
		}); err != nil {
			return err
		}
	}
	var controlErrors <-chan error
	controlCtx, cancelControl := context.WithCancel(ctx)
	var controlStopped <-chan struct{}
	defer func() {
		cancelControl()
		if controlStopped != nil {
			<-controlStopped
		}
	}()
	if cfg.BlockMode == config.BlockModeNFTables && opts.ControlSocketPath != "" {
		ch := make(chan error, 1)
		stopped := make(chan struct{})
		controlErrors = ch
		controlStopped = stopped
		go func() {
			defer close(stopped)
			ch <- control.Serve(controlCtx, opts.ControlSocketPath, manager)
		}()
	}
	follower, err := reader.Open(reader.Options{
		Path:          cfg.LogFile,
		StartPosition: reader.StartPosition(cfg.StartPosition),
	}, logger)
	if err != nil {
		return err
	}

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	lines := make(chan string, lineBufferSize)
	readerDone := make(chan error, 1)
	go func() {
		err := follower.Run(readerCtx, lines)
		close(lines)
		readerDone <- err
	}()

	logger.Info(
		"service started",
		"log_file", cfg.LogFile,
		"database_file", cfg.DatabasePath,
		"start_position", cfg.StartPosition,
		"block_mode", cfg.BlockMode,
		"block_duration", cfg.BlockDuration,
		"block_tcp_ports", cfg.BlockTCPPorts,
		"rules", len(rules),
		"analysis_config_id", analysisConfigID,
	)
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

	processEvent := func(event request.Event) error {
		if ruleEngine.IsIgnored(event) {
			return nil
		}
		if ruleEngine.IsLate(event.Timestamp) {
			statistics.lateEvents++
			if ruleEngine.Matches(event) {
				statistics.lateMatchingRequests++
			}
			if statistics.lateEvents == 1 {
				logger.Warn("late request excluded from rule windows", "timestamp", event.Timestamp)
			}
			return nil
		}

		statistics.engineProcessedRequests++
		evaluations, err := ruleEngine.Process(event)
		if err != nil {
			return err
		}
		if ruleEngine.Matches(event) {
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
				return fmt.Errorf("persist detection: %w", err)
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
		return nil
	}
	var processingError error
readLoop:
	for {
		select {
		case line, open := <-lines:
			if !open {
				break readLoop
			}
			statistics.linesRead++
			if opts.PrintLines {
				fmt.Fprintln(os.Stdout, line)
			}

			event, err := parser.ParseNginx(line)
			if err != nil {
				statistics.parseFailures++
				if opts.PrintEvents {
					logger.Warn("request parse failed", "error", err)
				}
				continue
			}
			statistics.parsedRequests++
			matches := ruleEngine.Matches(event)
			if matches {
				statistics.matchingRequests++
			}
			if opts.PrintEvents {
				logRequestEvent(logger, event)
			}
			metricCollector.Add(event, matches)

			if err := processEvent(event); err != nil {
				processingError = fmt.Errorf("process request: %w", err)
				break readLoop
			}
		case <-metricsTicker.C:
			if err := metricCollector.Flush(context.Background(), database); err != nil {
				processingError = fmt.Errorf("persist traffic statistics: %w", err)
				break readLoop
			}
		case now := <-expiryTick:
			ruleEngine.AdvanceWallClock(now)
		case serverErr := <-controlErrors:
			controlErrors = nil
			if serverErr != nil {
				processingError = fmt.Errorf("control socket: %w", serverErr)
				break readLoop
			}
		}
	}

	if processingError != nil {
		statistics.incomplete = true
		cancelReader()
		for range lines {
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
	ruleEngine.Cleanup()
	readerError := <-readerDone
	if processingError != nil {
		return processingError
	}
	if readerError != nil {
		statistics.incomplete = true
		return readerError
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
