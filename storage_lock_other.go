//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package stripelink

import (
	"context"
	"fmt"
	"os"
)

// The standard library has no portable cross-process file-lock API. On
// unsupported platforms FileStorage retains its per-instance synchronization
// and atomic replacement guarantees.
type storageLock struct {
	file *os.File
}

const crossProcessStorageLockSupported = false

func acquireStorageLock(ctx context.Context, path string) (*storageLock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("auth storage lock path is not a regular file: %s", path)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect auth storage lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open auth storage lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure auth storage lock: %w", err)
	}
	return &storageLock{file: file}, nil
}

func (l *storageLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func openCredentialFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
