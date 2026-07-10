//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package stripelink

import (
	"fmt"
	"os"
)

func syncDirectoryRaw(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	defer dir.Close()
	return dir.Sync()
}
