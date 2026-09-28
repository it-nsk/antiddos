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
	defaultRotationGrace     = 10 * time.Second
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
	RotationGrace     time.Duration
}

type logStream struct {
	file    *os.File
	offset  int64
	pending []byte
}

type drainingStream struct {
	stream     *logStream
	closeAfter time.Time
}

// Follower owns the active file and old file descriptors being drained after
// rotation. All mutable stream state is accessed by the Run goroutine.
// It is not safe to call Run more than once.
type Follower struct {
	path              string
	reconcileInterval time.Duration
	rotationGrace     time.Duration
	logger            *slog.Logger
	watcher           *fsnotify.Watcher
	active            *logStream
	draining          []*drainingStream
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
	if options.RotationGrace <= 0 {
		options.RotationGrace = defaultRotationGrace
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
		rotationGrace:     options.RotationGrace,
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

	if err := f.readAvailable(ctx, lines, f.active); err != nil {
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
	if err := f.drainRotated(ctx, lines); err != nil {
		return err
	}
	if err := f.readAvailable(ctx, lines, f.active); err != nil {
		return err
	}

	pathInfo, err := os.Stat(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat log path %q: %w", f.path, err)
	}

	if f.active == nil {
		if err := f.openCurrent(false); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return f.readAvailable(ctx, lines, f.active)
	}

	openInfo, err := f.active.file.Stat()
	if err != nil {
		return fmt.Errorf("stat open log %q: %w", f.path, err)
	}

	if os.SameFile(openInfo, pathInfo) {
		if pathInfo.Size() < f.active.offset {
			f.logger.Warn("log file was truncated; restarting at beginning", "path", f.path, "old_offset", f.active.offset, "new_size", pathInfo.Size())
			if _, err := f.active.file.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek truncated log %q: %w", f.path, err)
			}
			f.active.offset = 0
			f.dropPending(f.active, "truncation")
		}
		return f.readAvailable(ctx, lines, f.active)
	}

	if err := f.readAvailable(ctx, lines, f.active); err != nil {
		return err
	}
	old := f.active
	if err := f.openCurrent(false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			f.logger.Warn("new log disappeared during rotation; waiting for creation", "path", f.path)
			return nil
		}
		return err
	}
	f.beginRotationDrain(old)
	return f.readAvailable(ctx, lines, f.active)
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

	f.active = &logStream{
		file:   file,
		offset: offset,
	}
	f.logger.Info("log file opened", "path", f.path, "offset", offset)
	return nil
}

func (f *Follower) readAvailable(ctx context.Context, lines chan<- string, stream *logStream) error {
	if stream == nil {
		return nil
	}

	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := stream.file.Read(buffer)
		if read > 0 {
			stream.offset += int64(read)
			stream.pending = append(stream.pending, buffer[:read]...)
			if err := f.emitCompleteLines(ctx, lines, stream); err != nil {
				return err
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read log %q at offset %d: %w", stream.file.Name(), stream.offset, err)
		}
		if read == 0 {
			return nil
		}
	}
}

func (f *Follower) emitCompleteLines(ctx context.Context, lines chan<- string, stream *logStream) error {
	for {
		newline := bytes.IndexByte(stream.pending, '\n')
		if newline < 0 {
			return nil
		}

		line := stream.pending[:newline]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		select {
		case lines <- string(line):
			stream.pending = stream.pending[newline+1:]
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (f *Follower) beginRotationDrain(old *logStream) {
	closeAfter := time.Now().Add(f.rotationGrace)
	f.draining = append(f.draining, &drainingStream{
		stream:     old,
		closeAfter: closeAfter,
	})
	f.logger.Info(
		"log file rotated; draining old inode",
		"path", f.path,
		"offset", old.offset,
		"grace", f.rotationGrace,
	)
}

func (f *Follower) drainRotated(ctx context.Context, lines chan<- string) error {
	remaining := f.draining[:0]
	for index, draining := range f.draining {
		previousOffset := draining.stream.offset
		if err := f.readAvailable(ctx, lines, draining.stream); err != nil {
			f.draining = append(remaining, f.draining[index:]...)
			return err
		}
		// EOF only describes the current end: the writer may still hold this
		// inode. Require a full quiet period after every observed append.
		now := time.Now()
		if draining.stream.offset != previousOffset {
			draining.closeAfter = now.Add(f.rotationGrace)
		}
		if now.Before(draining.closeAfter) {
			remaining = append(remaining, draining)
			continue
		}

		f.dropPending(draining.stream, "rotation grace expired")
		if err := draining.stream.file.Close(); err != nil {
			f.logger.Error("close drained log", "path", draining.stream.file.Name(), "error", err)
			continue
		}
		f.logger.Info("rotated log drained and closed", "path", draining.stream.file.Name(), "offset", draining.stream.offset)
	}
	clear(f.draining[len(remaining):])
	f.draining = remaining
	return nil
}

func (f *Follower) dropPending(stream *logStream, reason string) {
	if len(stream.pending) > 0 {
		f.logger.Warn("discarding incomplete line", "path", stream.file.Name(), "bytes", len(stream.pending), "reason", reason)
	}
	stream.pending = nil
}

func (f *Follower) close() {
	if f.active != nil {
		if err := f.active.file.Close(); err != nil {
			f.logger.Error("close log file", "path", f.path, "error", err)
		}
	}
	for _, draining := range f.draining {
		if err := draining.stream.file.Close(); err != nil {
			f.logger.Error("close rotated log file", "path", draining.stream.file.Name(), "error", err)
		}
	}
	if err := f.watcher.Close(); err != nil {
		f.logger.Error("close filesystem watcher", "error", err)
	}
}
