package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/it-nsk/antiddos/internal/config"
	"github.com/it-nsk/antiddos/internal/reader"
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
		return fmt.Errorf("usage: antiddos run [--config PATH] [--from-start] [--print-lines]")
	}

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", config.DefaultPath, "path to JSON configuration")
	fromStart := flags.Bool("from-start", false, "override start_position and read the existing file from the beginning")
	printLines := flags.Bool("print-lines", false, "print every complete input line; intended only for development")
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

	follower, err := reader.Open(reader.Options{
		Path:          cfg.LogFile,
		StartPosition: reader.StartPosition(cfg.StartPosition),
	}, logger)
	if err != nil {
		return err
	}

	lines := make(chan string, lineBufferSize)
	readerDone := make(chan error, 1)
	go func() {
		err := follower.Run(ctx, lines)
		close(lines)
		readerDone <- err
	}()

	logger.Info("service started", "log_file", cfg.LogFile, "start_position", cfg.StartPosition)
	var linesRead uint64
	defer func() {
		logger.Info("service stopped", "lines_read", linesRead)
	}()

	for line := range lines {
		linesRead++
		if *printLines {
			fmt.Fprintln(os.Stdout, line)
		}
	}

	return <-readerDone
}
