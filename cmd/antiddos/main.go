package main

import (
	"context"
	"flag"
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
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := execute(ctx, os.Args[1:], logger); err != nil {
		logger.Error("service failed", "error", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: antiddos run [--config PATH] [--from-start] [--print-lines] [--print-events]")
	}

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", config.DefaultPath, "path to JSON configuration")
	fromStart := flags.Bool("from-start", false, "override start_position and read the existing file from the beginning")
	printLines := flags.Bool("print-lines", false, "print every complete input line; intended only for development")
	printEvents := flags.Bool("print-events", false, "print every parsed request event; intended only for development")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *fromStart {
		cfg.StartPosition = string(reader.StartAtBeginning)
	}
	rules := make([]engine.Rule, len(cfg.Engine.Rules))
	for ruleIndex, configuredRule := range cfg.Engine.Rules {
		groupings := make([]engine.Grouping, len(configuredRule.Groupings))
		for groupingIndex, configuredGrouping := range configuredRule.Groupings {
			fields := make([]engine.GroupField, len(configuredGrouping.Fields))
			for fieldIndex, field := range configuredGrouping.Fields {
				fields[fieldIndex] = engine.GroupField(field)
			}
			groupings[groupingIndex] = engine.Grouping{ID: configuredGrouping.ID, Fields: fields}
		}
		rules[ruleIndex] = engine.Rule{
			ID:                  configuredRule.ID,
			Window:              configuredRule.Window,
			Threshold:           configuredRule.Threshold,
			SuspiciousThreshold: configuredRule.SuspiciousThreshold,
			Groupings:           groupings,
		}
	}
	liveTail := cfg.StartPosition == string(reader.StartAtEnd)
	ruleEngine, err := engine.NewWithOptions(rules, engine.Options{
		LiveClock:        liveTail,
		MaxEventLateness: cfg.Engine.LiveEventLateness,
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
			"matching_homepage_requests", statistics.matchingHomepageRequests,
			"engine_processed_requests", statistics.engineProcessedRequests,
			"evaluated_homepage_requests", statistics.evaluatedHomepageRequests,
			"late_events", statistics.lateEvents,
			"late_homepage_requests", statistics.lateHomepageRequests,
			"violating_requests", statistics.violatingRequests,
			"violating_evaluations", statistics.violatingEvaluations,
			"emitted_detections", statistics.emittedDetections,
			"suspicious_detections", statistics.suspiciousDetections,
			"threshold_detections", statistics.thresholdDetections,
			"unprocessed_lines", statistics.unprocessedLines,
			"incomplete", statistics.incomplete,
		)
	}()

	processEvent := func(event request.Event) error {
		if ruleEngine.IsLate(event.Timestamp) {
			statistics.lateEvents++
			if engine.IsHomepageRequest(event) {
				statistics.lateHomepageRequests++
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
		if engine.IsHomepageRequest(event) {
			statistics.evaluatedHomepageRequests++
		}
		violating := false
		for _, evaluation := range evaluations {
			if evaluation.Severity == engine.SeverityThresholdExceeded {
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
			switch evaluation.Detection.Severity {
			case engine.SeveritySuspicious:
				statistics.suspiciousDetections++
			case engine.SeverityThresholdExceeded:
				statistics.thresholdDetections++
			}
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
			if *printLines {
				fmt.Fprintln(os.Stdout, line)
			}

			event, err := parser.ParseNginx(line)
			if err != nil {
				statistics.parseFailures++
				if *printEvents {
					logger.Warn("request parse failed", "error", err)
				}
				continue
			}
			statistics.parsedRequests++
			if engine.IsHomepageRequest(event) {
				statistics.matchingHomepageRequests++
			}
			if *printEvents {
				logRequestEvent(logger, event)
			}
			metricCollector.Add(event, engine.IsHomepageRequest(event))

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
		logger.Warn("analysis excluded late requests", "late_events", statistics.lateEvents, "late_homepage_requests", statistics.lateHomepageRequests)
	}
	return nil
}

type runStatistics struct {
	linesRead                 uint64
	parsedRequests            uint64
	parseFailures             uint64
	matchingHomepageRequests  uint64
	engineProcessedRequests   uint64
	evaluatedHomepageRequests uint64
	lateEvents                uint64
	lateHomepageRequests      uint64
	violatingRequests         uint64
	violatingEvaluations      uint64
	emittedDetections         uint64
	suspiciousDetections      uint64
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
		"grouping", detection.GroupingID,
		"group_fields", detection.GroupFields,
		"group_values", detection.GroupValues,
		"group", detection.GroupKey,
		"event_timestamp", detection.EventTimestamp,
		"emitted_at", time.Now(),
		"count", detection.Count,
		"window", detection.Window,
		"threshold", detection.Threshold,
		"suspicious_threshold", detection.SuspiciousThreshold,
		"severity", detection.Severity,
		"dry_run", detection.DryRun,
	)
}
