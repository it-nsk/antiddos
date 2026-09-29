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
	"github.com/it-nsk/antiddos/internal/ordering"
	"github.com/it-nsk/antiddos/internal/parser"
	"github.com/it-nsk/antiddos/internal/reader"
	"github.com/it-nsk/antiddos/internal/request"
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
	ruleEngine, err := engine.New(rules)
	if err != nil {
		return fmt.Errorf("initialize rule engine: %w", err)
	}
	orderBuffer, err := ordering.New(cfg.Engine.AllowedLateness, cfg.Engine.MaxPendingEvents)
	if err != nil {
		return fmt.Errorf("initialize ordering buffer: %w", err)
	}
	analysisConfigID := engine.AnalysisConfigID(
		ruleEngine.RuleRevisions(),
		cfg.Engine.AllowedLateness,
		cfg.Engine.MaxPendingEvents,
	)

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
		"start_position", cfg.StartPosition,
		"rules", len(rules),
		"allowed_lateness", cfg.Engine.AllowedLateness,
		"max_pending_events", cfg.Engine.MaxPendingEvents,
		"analysis_config_id", analysisConfigID,
	)
	statistics := runStatistics{}
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
			"buffered_events", statistics.bufferedEvents,
			"unprocessed_lines", statistics.unprocessedLines,
			"incomplete", statistics.incomplete,
		)
	}()

	var ticker *time.Ticker
	var tick <-chan time.Time
	if cfg.Engine.AllowedLateness > 0 {
		interval := min(cfg.Engine.AllowedLateness, 100*time.Millisecond)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
		tick = ticker.C
	}

	processOrderedEvent := func(event request.Event) error {
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
	processOrdered := func(events []request.Event) error {
		for _, event := range events {
			if err := processOrderedEvent(event); err != nil {
				return err
			}
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

			result, err := orderBuffer.Push(event, time.Now())
			if orderedErr := processOrdered(result.Ready); orderedErr != nil {
				processingError = fmt.Errorf("process ordered request: %w", orderedErr)
				break readLoop
			}
			if result.HasImmediate {
				if orderedErr := processOrderedEvent(result.Immediate); orderedErr != nil {
					processingError = fmt.Errorf("process ordered request: %w", orderedErr)
					break readLoop
				}
			}
			if result.Late {
				statistics.lateEvents++
				if engine.IsHomepageRequest(event) {
					statistics.lateHomepageRequests++
				}
				if statistics.lateEvents == 1 {
					logger.Warn("late request excluded from rule windows", "timestamp", event.Timestamp)
				}
			}
			if err != nil {
				processingError = err
				break readLoop
			}
		case now := <-tick:
			if err := processOrdered(orderBuffer.DrainReady(now)); err != nil {
				processingError = fmt.Errorf("process ordered request: %w", err)
				break readLoop
			}
		}
	}

	if processingError != nil {
		statistics.incomplete = true
		statistics.bufferedEvents = uint64(orderBuffer.Pending())
		cancelReader()
		for range lines {
			statistics.unprocessedLines++
		}
	} else if err := processOrdered(orderBuffer.Flush()); err != nil {
		statistics.incomplete = true
		processingError = fmt.Errorf("flush ordered requests: %w", err)
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
	bufferedEvents            uint64
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
		"outcome", detection.Outcome,
	)
}
