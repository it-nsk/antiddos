//go:build linux

package webui

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// applyHistoryPriority pins the import goroutine to a dedicated OS thread.
// The caller deliberately keeps it pinned until the goroutine returns, so a
// lowered nice value cannot leak to an unrelated web request.
func applyHistoryPriority(nice, ioLevel int) error {
	if nice < 0 || nice > 19 || ioLevel < 0 || ioLevel > 7 {
		return fmt.Errorf("history nice must be 0-19 and I/O priority level 0-7")
	}
	runtime.LockOSThread()
	tid := unix.Gettid()
	if err := unix.Setpriority(unix.PRIO_PROCESS, tid, nice); err != nil {
		return fmt.Errorf("set historical CPU nice: %w", err)
	}
	// IOPRIO_WHO_PROCESS=1, best-effort class=2, data=0..7.
	if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(tid), uintptr(2<<13|ioLevel)); errno != 0 {
		return fmt.Errorf("set historical I/O priority: %w", errno)
	}
	return nil
}
