//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package stripelink

// syncDirectoryRaw is a deliberate durability boundary on platforms where
// the Go standard library cannot portably fsync a directory. The credential
// file itself is still synced before atomic replacement. Tests can replace
// the per-instance operation to verify directory-sync error handling on every
// platform.
func syncDirectoryRaw(string) error { return nil }
