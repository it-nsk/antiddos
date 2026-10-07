package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/engine"
	"github.com/it-nsk/antiddos/internal/metrics"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/reader"
	"github.com/it-nsk/antiddos/internal/request"
	"github.com/it-nsk/antiddos/internal/storage"
)

const lineBufferSize = 256

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := execute(ctx, os.Args[1:], logger); err != nil {
		logger.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	opts, err := parseRunFlags(args[1:], os.Stderr)
	if err != nil {
		return err
	}

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
	})
	if err != nil {
		return fmt.Errorf("initialize rule engine: %w", err)
	}
	if liveTail {
		ruleEngine.AdvanceWallClock(time.Now())
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
		"rules", len(rules),
		"analysis_config_id", analysisConfigID,
	)
	statistics := runStatistics{}
	metricCollector := metrics.NewCollector()
	metricsTicker := time.NewTicker(metrics.SampleInterval)
	defer metricsTicker.Stop()
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
