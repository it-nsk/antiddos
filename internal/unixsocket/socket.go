// Package unixsocket creates bounded-permission Unix sockets without replacing
// regular files or unlinking a path that another process has taken over.
package unixsocket

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func Listen(path string, directoryMode, socketMode os.FileMode, groupID int) (net.Listener, func() error, error) {
	if path == "" || !filepath.IsAbs(path) || directoryMode&^os.ModePerm != 0 || socketMode&^os.ModePerm != 0 {
		return nil, nil, fmt.Errorf("invalid Unix socket path or permissions")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return nil, nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Chmod(directory, directoryMode); err != nil {
		return nil, nil, fmt.Errorf("set socket directory mode: %w", err)
	}
	if groupID >= 0 {
		if err := os.Chown(directory, -1, groupID); err != nil {
			return nil, nil, fmt.Errorf("set socket directory group: %w", err)
		}
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("refusing to replace non-socket path %q", path)
		}
		connection, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, nil, fmt.Errorf("socket %q is already active", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("inspect socket path: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	if groupID >= 0 {
		if err := os.Chown(path, -1, groupID); err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, nil, fmt.Errorf("set socket group: %w", err)
		}
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, fmt.Errorf("set socket mode: %w", err)
	}
	owned, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("inspect created socket: %w", err)
	}
	cleanup := func() error {
		current, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !os.SameFile(owned, current) {
			return fmt.Errorf("socket path %q changed ownership; refusing to unlink", path)
		}
		return os.Remove(path)
	}
	return listener, cleanup, nil
}
