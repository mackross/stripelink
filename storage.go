package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type storageGate struct {
	once sync.Once
	ch   chan struct{}
}

func (g *storageGate) lock(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	g.once.Do(func() {
		g.ch = make(chan struct{}, 1)
		g.ch <- struct{}{}
	})
	if err := contextFailure(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return contextFailure(ctx)
	case <-g.ch:
		if err := contextFailure(ctx); err != nil {
			g.ch <- struct{}{}
			return err
		}
		return nil
	}
}

func (g *storageGate) unlock() { g.ch <- struct{}{} }

// maxAuthFileBytes bounds credential-file reads. Auth state is only a few
// kilobytes; a larger file is corrupt or hostile and is never decoded.
const maxAuthFileBytes int64 = 1 << 20

// PendingDeviceAuth records an in-progress device authorization so a login
// flow can be resumed across process restarts (parity: utils/storage.ts:6-12).
type PendingDeviceAuth struct {
	DeviceCode string `json:"device_code"`

	// Interval is the minimum polling interval in seconds.
	Interval int `json:"interval"`

	// ExpiresAt is the absolute expiry of the device code in epoch
	// milliseconds.
	ExpiresAt int64 `json:"expires_at"`

	VerificationURL string `json:"verification_url"`
	Phrase          string `json:"phrase"`
}

// String returns a credential-safe summary of a pending device flow.
func (p PendingDeviceAuth) String() string {
	return fmt.Sprintf("PendingDeviceAuth{DeviceCode:<redacted> Interval:%d ExpiresAt:%d VerificationURL:<redacted> Phrase:<redacted>}", p.Interval, p.ExpiresAt)
}

// Format makes every fmt verb use the credential-safe summary.
func (p PendingDeviceAuth) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(p.String())) }

// AuthStorage is the SDK's extension point for complete, transactional auth
// state storage. Implementations must be safe for concurrent use and return
// defensive copies from Load and at the Transact callback boundary.
type AuthStorage interface {
	// Load returns a defensive copy of the complete stored state. Missing state
	// is returned as a non-nil zero AuthStorageState.
	Load(context.Context) (*AuthStorageState, error)

	// Transact executes update while holding the storage's exclusive session
	// lock and, when update returns nil, commits the complete resulting state as
	// one atomic operation. The callback receives defensive copies and must not
	// call back into this storage, perform network I/O, or have external side
	// effects. If the context is canceled while waiting for the lock, while the
	// callback is running, or before the durable commit, the state is not changed.
	//
	// Implementations must coordinate Load, Transact, and Clear using the same
	// lock. Persistent implementations must extend that lock across cooperating
	// processes and keep it held through durable replacement. This prevents
	// local lost updates when multiple Clients share a custom store; it does not
	// serialize their network refresh requests.
	Transact(context.Context, func(*AuthStorageState) error) error

	// Clear atomically removes all stored auth and pending device-flow state.
	// Calling Clear when no state exists succeeds.
	Clear(context.Context) error
}

// AuthStorageState is the complete mutable session snapshot supplied to an
// AuthStorage.Transact callback. Its fields contain credentials and must never
// be logged. DeviceAuthGeneration is storage metadata used to reject stale
// device-flow responses; custom stores must persist it with the other fields.
type AuthStorageState struct {
	Auth                 *AuthTokens        `json:"auth"`
	PendingDeviceAuth    *PendingDeviceAuth `json:"pendingDeviceAuth"`
	DeviceAuthGeneration uint64             `json:"deviceAuthGeneration"`
}

// String returns a credential-safe transaction-state summary.
func (s AuthStorageState) String() string {
	return fmt.Sprintf("AuthStorageState{Auth:<redacted> PendingDeviceAuth:<redacted> DeviceAuthGeneration:%d}", s.DeviceAuthGeneration)
}

// Format makes every fmt verb use the credential-safe summary.
func (s AuthStorageState) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(s.String())) }

// Compile-time interface conformance checks.
var (
	_ AuthStorage = (*FileStorage)(nil)
	_ AuthStorage = (*MemoryStorage)(nil)
)

// FileStorage is an AuthStorage backed by a JSON file that is byte-compatible
// with the JS CLI's conf file: {"auth": {...}|null, "pendingDeviceAuth":
// {...}|null}, with expires_at in epoch milliseconds — pointing the Go SDK at
// an existing link-cli auth file works. The file holds OAuth access and
// refresh tokens and, during the device-auth window, a device code, so mode
// 0600 is enforced on create and on every write; writes are durable and
// atomic (same-directory temp file, fsync, rename, then directory fsync).
// Reads are capped at 1 MiB and reject oversized files. FileStorage is safe
// for concurrent use. On platforms with standard-library advisory locking,
// separate instances and processes coordinate scoped read-modify-write
// operations through an owner-only companion lock file.
type FileStorage struct {
	gate storageGate
	path string
	ops  storageFileOps
}

// storageFileOps is a per-instance, unexported filesystem boundary. Production
// instances always receive the real operations from NewFileStorage; tests use
// it to exercise otherwise nondeterministic durability failures without
// package-level mutable hooks or an unsafe public option.
type storageFileOps struct {
	marshal       func(any) ([]byte, error)
	createTemp    func(string, string) (*os.File, error)
	write         func(*os.File, []byte) (int, error)
	sync          func(*os.File) error
	close         func(*os.File) error
	rename        func(string, string) error
	syncDirectory func(string) error
}

func defaultStorageFileOps() storageFileOps {
	return storageFileOps{
		marshal:       json.Marshal,
		createTemp:    os.CreateTemp,
		write:         func(file *os.File, data []byte) (int, error) { return file.Write(data) },
		sync:          func(file *os.File) error { return file.Sync() },
		close:         func(file *os.File) error { return file.Close() },
		rename:        os.Rename,
		syncDirectory: syncDirectoryRaw,
	}
}

// NewFileStorage returns a FileStorage persisting to the file at path. An
// empty path selects the default location, os.UserConfigDir()-based
// stripelink/auth.json; the returned error reports a failure to resolve the
// user config directory.
func NewFileStorage(path string) (*FileStorage, error) {
	if path == "" {
		root, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("resolve user config directory: %w", err)
		}
		path = filepath.Join(root, "stripelink", "auth.json")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve auth storage path: %w", err)
	}
	return &FileStorage{path: filepath.Clean(abs), ops: defaultStorageFileOps()}, nil
}

// Path returns the file path backing this storage.
func (s *FileStorage) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Delete removes the backing file. A missing file is treated as success
// (parity: storage.ts:133-139). Cancellation is honored while waiting for the
// in-process or cross-process storage lock and before the file is removed.
func (s *FileStorage) Delete(ctx context.Context) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if err := s.gate.lock(ctx); err != nil {
		return err
	}
	defer s.gate.unlock()

	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect auth storage file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("auth storage path is not a regular file: %s", s.path)
	}

	lock, err := acquireStorageLock(ctx, s.path+".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := contextFailure(ctx); err != nil {
		return err
	}

	info, err = os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect auth storage file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("auth storage path is not a regular file: %s", s.path)
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete auth storage file: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

// Load returns a defensive copy of the complete stored auth state.
func (s *FileStorage) Load(ctx context.Context) (*AuthStorageState, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	var snapshot *AuthStorageState
	err := s.withState(ctx, false, func(raw storageState, _ bool) (bool, error) {
		var err error
		snapshot, err = raw.snapshot()
		return false, err
	})
	return snapshot, err
}

// Transact performs a cross-instance, and on supported Unix platforms
// cross-process, atomic session transaction.
func (s *FileStorage) Transact(ctx context.Context, update func(*AuthStorageState) error) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if update == nil {
		return fmt.Errorf("%w: storage transaction callback is required", ErrInvalidArgument)
	}
	return s.withState(ctx, true, func(raw storageState, _ bool) (bool, error) {
		state, err := raw.snapshot()
		if err != nil {
			return false, err
		}
		if err := update(state); err != nil {
			return false, err
		}
		if err := contextFailure(ctx); err != nil {
			return false, err
		}
		before, err := json.Marshal(raw)
		if err != nil {
			return false, fmt.Errorf("encode auth storage state: %w", err)
		}
		if err := raw.replaceSnapshot(state); err != nil {
			return false, err
		}
		after, err := json.Marshal(raw)
		if err != nil {
			return false, fmt.Errorf("encode auth storage state: %w", err)
		}
		return !bytes.Equal(before, after), nil
	})
}

// Clear atomically removes all stored auth and pending device-flow state.
func (s *FileStorage) Clear(ctx context.Context) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(ctx, false, func(state storageState, exists bool) (bool, error) {
		if !exists {
			return false, nil
		}
		for key := range state {
			delete(state, key)
		}
		state["auth"] = json.RawMessage("null")
		state["pendingDeviceAuth"] = json.RawMessage("null")
		state.bumpDeviceAuthGeneration()
		return true, nil
	})
}
