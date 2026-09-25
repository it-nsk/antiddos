package reader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	defaultEventBuffer       = 256
	defaultReconcileInterval = time.Second
)

type StartPosition string

const (
	StartAtBeginning StartPosition = "beginning"
	StartAtEnd       StartPosition = "end"
)

type Options struct {
	Path              string
	StartPosition     StartPosition
	ReconcileInterval time.Duration
}

// Follower owns the watched file, its offset, and any incomplete final line.
// It is not safe to call Run more than once.
type Follower struct {
	path              string
	reconcileInterval time.Duration
	logger            *slog.Logger
	watcher           *fsnotify.Watcher
	file              *os.File
	offset            int64
	pending           []byte
}

func Open(options Options, logger *slog.Logger) (*Follower, error) {
	if options.StartPosition != StartAtBeginning && options.StartPosition != StartAtEnd {
		return nil, fmt.Errorf("unsupported start position %q", options.StartPosition)
	}
	if !filepath.IsAbs(options.Path) {
		return nil, fmt.Errorf("log path must be absolute")
	}
	if options.ReconcileInterval <= 0 {
		options.ReconcileInterval = defaultReconcileInterval
	}
	if logger == nil {
		logger = slog.Default()
	}

	watcher, err := fsnotify.NewBufferedWatcher(defaultEventBuffer)
	if err != nil {
		return nil, fmt.Errorf("create filesystem watcher: %w", err)
	}

	follower := &Follower{
		path:              filepath.Clean(options.Path),
		reconcileInterval: options.ReconcileInterval,
		logger:            logger,
		watcher:           watcher,
	}

	if err := watcher.Add(filepath.Dir(follower.path)); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch log directory %q: %w", filepath.Dir(follower.path), err)
	}

	seekEnd := options.StartPosition == StartAtEnd
	if err := follower.openCurrent(seekEnd); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			follower.logger.Warn("log file does not exist; waiting for creation", "path", follower.path)
			return follower, nil
		}
		watcher.Close()
		return nil, err
	}

	return follower, nil
}

func (f *Follower) Run(ctx context.Context, lines chan<- string) error {
	defer f.close()

	if err := f.readAvailable(ctx, lines); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	ticker := time.NewTicker(f.reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-f.watcher.Events:
			if !ok {
				return fmt.Errorf("filesystem event channel closed")
			}
			if filepath.Clean(event.Name) != f.path {
				continue
			}
			if err := f.reconcile(ctx, lines); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case err, ok := <-f.watcher.Errors:
			if !ok {
				return fmt.Errorf("filesystem error channel closed")
			}
			f.logger.Error("filesystem notification error; periodic reconciliation remains active", "error", err)
		case <-ticker.C:
			if err := f.reconcile(ctx, lines); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

func (f *Follower) reconcile(ctx context.Context, lines chan<- string) error {
	if err := f.readAvailable(ctx, lines); err != nil {
		return err
	}

	pathInfo, err := os.Stat(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat log path %q: %w", f.path, err)
	}

	if f.file == nil {
		if err := f.openCurrent(false); err != nil {
			return err
		}
		return f.readAvailable(ctx, lines)
	}

	openInfo, err := f.file.Stat()
	if err != nil {
		return fmt.Errorf("stat open log %q: %w", f.path, err)
	}

	if os.SameFile(openInfo, pathInfo) {
		if pathInfo.Size() < f.offset {
			f.logger.Warn("log file was truncated; restarting at beginning", "path", f.path, "old_offset", f.offset, "new_size", pathInfo.Size())
			if _, err := f.file.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek truncated log %q: %w", f.path, err)
			}
			f.offset = 0
			f.dropPending("truncation")
		}
		return f.readAvailable(ctx, lines)
	}

	if err := f.readAvailable(ctx, lines); err != nil {
		return err
	}
	f.dropPending("rotation")
	if err := f.file.Close(); err != nil {
		return fmt.Errorf("close rotated log %q: %w", f.path, err)
	}
	f.file = nil

	if err := f.openCurrent(false); err != nil {
		return err
	}
	return f.readAvailable(ctx, lines)
}

func (f *Follower) openCurrent(seekEnd bool) error {
	file, err := os.Open(f.path)
	if err != nil {
		return fmt.Errorf("open log %q: %w", f.path, err)
	}

	offset := int64(0)
	if seekEnd {
		offset, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			file.Close()
			return fmt.Errorf("seek to end of log %q: %w", f.path, err)
		}
	}

	f.file = file
	f.offset = offset
	f.pending = nil
	f.logger.Info("log file opened", "path", f.path, "offset", offset)
	return nil
}

func (f *Follower) readAvailable(ctx context.Context, lines chan<- string) error {
	if f.file == nil {
		return nil
	}

	buffer := make([]byte, 64*1024)
	for {
		read, err := f.file.Read(buffer)
		if read > 0 {
			f.offset += int64(read)
			f.pending = append(f.pending, buffer[:read]...)
			if err := f.emitCompleteLines(ctx, lines); err != nil {
				return err
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read log %q at offset %d: %w", f.path, f.offset, err)
		}
		if read == 0 {
			return nil
		}
	}
}

func (f *Follower) emitCompleteLines(ctx context.Context, lines chan<- string) error {
	for {
		newline := bytes.IndexByte(f.pending, '\n')
		if newline < 0 {
			return nil
		}

		line := f.pending[:newline]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		select {
		case lines <- string(line):
			f.pending = f.pending[newline+1:]
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (f *Follower) dropPending(reason string) {
	if len(f.pending) > 0 {
		f.logger.Warn("discarding incomplete line", "path", f.path, "bytes", len(f.pending), "reason", reason)
	}
	f.pending = nil
}

func (f *Follower) close() {
	if f.file != nil {
		if err := f.file.Close(); err != nil {
			f.logger.Error("close log file", "path", f.path, "error", err)
		}
	}
	if err := f.watcher.Close(); err != nil {
		f.logger.Error("close filesystem watcher", "error", err)
	}
}
