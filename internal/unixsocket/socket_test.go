package unixsocket

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestListenSetsPrivateDirectoryAndSocketModesAndCleansOnlyItsSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed", "feed.sock")
	listener, cleanup, err := Listen(path, 0750, 0660, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0750 {
		t.Fatalf("directory mode=%o", directory.Mode().Perm())
	}
	socket, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if socket.Mode().Perm() != 0660 || socket.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode=%v", socket.Mode())
	}
	if socket.Sys().(*syscall.Stat_t).Gid != uint32(os.Getgid()) {
		t.Fatalf("socket GID=%d", socket.Sys().(*syscall.Stat_t).Gid)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	listener.Close()
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket remains or lookup failed: %v", err)
	}
}

func TestListenRefusesRegularFileAndActiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Listen(path, 0750, 0660, -1); err == nil {
		t.Fatal("replaced regular file")
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != "keep" {
		t.Fatalf("regular file changed: %q err=%v", contents, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, cleanup, err := Listen(path, 0750, 0660, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer listener.Close()
	if _, _, err := Listen(path, 0750, 0660, -1); err == nil {
		t.Fatal("allowed duplicate active socket")
	}
}
