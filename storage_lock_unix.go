//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package stripelink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

type storageLock struct {
	file *os.File
}

const crossProcessStorageLockSupported = true

func acquireStorageLock(ctx context.Context, path string) (*storageLock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open auth storage lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(operation string, cause error) (*storageLock, error) {
		_ = file.Close()
		return nil, fmt.Errorf("%s auth storage lock: %w", operation, cause)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fail("inspect", err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fail("validate", fmt.Errorf("path is not a regular file: %s", path))
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return fail("secure", err)
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fail("acquire", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fail("acquire", contextFailure(ctx))
		case <-timer.C:
		}
	}
	return &storageLock{file: file}, nil
}

func (l *storageLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	fd := int(l.file.Fd())
	unlockErr := syscall.Flock(fd, syscall.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("release auth storage lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close auth storage lock: %w", closeErr)
	}
	return nil
}

func openCredentialFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = file.Close()
		return nil, fmt.Errorf("path is not a regular file: %s", path)
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
