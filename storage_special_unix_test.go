//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package stripelink

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileStorageRejectsDeviceAndFIFOWithoutOpening(t *testing.T) {
	for name, path := range map[string]string{
		"character device": "/dev/null",
		"fifo":             filepath.Join(t.TempDir(), "credentials.fifo"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "fifo" {
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			storage, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.GetAuth(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("GetAuth error = %v", err)
			}
			if err := storage.SetAuth(validAuth()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("SetAuth error = %v", err)
			}
			if err := storage.Delete(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("Delete error = %v", err)
			}
		})
	}
}

func TestFileStorageReportsUnreadablePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unreadable")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte(`{"auth":null,"pendingDeviceAuth":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.GetAuth()
	if err == nil {
		t.Skip("test process can bypass directory permissions")
	}
	if !strings.Contains(err.Error(), "inspect auth storage file") && !strings.Contains(err.Error(), "open auth storage file") {
		t.Fatalf("imprecise unreadable-path error: %v", err)
	}
}
