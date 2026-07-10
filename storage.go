package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
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

// GoString returns the credential-safe structural summary.
func (p PendingDeviceAuth) GoString() string { return p.String() }

// Format makes every fmt verb use the credential-safe summary.
func (p PendingDeviceAuth) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(p.String())) }

// AuthStorage persists OAuth tokens and pending device authorizations. It is
// the SDK's deliberate extension point for custom credential stores.
// Implementations must be safe for concurrent use.
// Get methods and Set methods must make defensive copies: callers must never
// receive aliases to storage-owned values or transfer mutable aliases into a
// storage implementation.
//
// Unlike the JS interface, AuthStorage has no path or delete methods — those
// are file-storage concerns and exist only on *FileStorage as Path and Delete
// (GUIDANCE §5.6, §6.2 deviation #7). Callers holding the interface who need
// the path can type-assert to *FileStorage.
type AuthStorage interface {
	// GetAuth returns a defensive copy of the stored tokens, or (nil, nil)
	// when not authenticated.
	GetAuth() (*AuthTokens, error)

	// SetAuth stores a defensive copy of the tokens, computing ExpiresAt from
	// ExpiresIn when ExpiresAt is zero (parity: storage.ts:35).
	SetAuth(*AuthTokens) error

	// ClearAuth removes the stored tokens.
	ClearAuth() error

	// GetPendingDeviceAuth returns a defensive copy of the stored pending device authorization.
	// Expired entries are cleared and (nil, nil) is returned (parity:
	// storage.ts:107-115).
	GetPendingDeviceAuth() (*PendingDeviceAuth, error)

	// SetPendingDeviceAuth stores a defensive copy of the pending device authorization.
	SetPendingDeviceAuth(*PendingDeviceAuth) error

	// ClearPendingDeviceAuth removes the stored pending device authorization.
	ClearPendingDeviceAuth() error

	// ClearAll removes everything held by the storage.
	ClearAll() error

	// Update executes update while holding the storage's exclusive session
	// lock and, when update returns nil, commits the complete resulting state as
	// one atomic operation. The callback receives defensive copies and must not
	// call back into this storage. If the context is canceled while waiting for
	// the lock, while the callback is running, or before the durable commit, the
	// state is not changed.
	//
	// Implementations must coordinate every Update using the same lock as the
	// ordinary Get/Set/Clear methods. Persistent implementations must extend
	// that lock across cooperating processes and keep it held through durable
	// replacement. This requirement is what makes rotating refresh tokens safe
	// when multiple Clients share a custom storage implementation.
	Update(context.Context, func(*AuthStorageState) error) error
}

// AuthStorageState is the complete mutable session snapshot supplied to an
// AuthStorage.Update callback. Its fields contain credentials and must never
// be logged. DeviceAuthGeneration is storage metadata used to reject stale
// device-flow responses; custom stores must persist it with the other fields.
type AuthStorageState struct {
	Auth                 *AuthTokens
	PendingDeviceAuth    *PendingDeviceAuth
	DeviceAuthGeneration uint64
}

// String returns a credential-safe transaction-state summary.
func (s AuthStorageState) String() string {
	return fmt.Sprintf("AuthStorageState{Auth:<redacted> PendingDeviceAuth:<redacted> DeviceAuthGeneration:%d}", s.DeviceAuthGeneration)
}

// GoString returns the credential-safe structural summary.
func (s AuthStorageState) GoString() string { return s.String() }

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
// (parity: storage.ts:133-139).
func (s *FileStorage) Delete() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if err := s.gate.lock(context.Background()); err != nil {
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

	lock, err := acquireStorageLock(context.Background(), s.path+".lock")
	if err != nil {
		return err
	}
	defer lock.Close()

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

// GetAuth returns the stored tokens, or (nil, nil) when not authenticated.
func (s *FileStorage) GetAuth() (*AuthTokens, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	var auth *AuthTokens
	err := s.withState(context.Background(), false, func(state storageState, _ bool) (bool, error) {
		var err error
		auth, err = state.auth()
		return false, err
	})
	return auth, err
}

// SetAuth stores the tokens, computing ExpiresAt from ExpiresIn when
// ExpiresAt is zero.
func (s *FileStorage) SetAuth(auth *AuthTokens) error {
	copy, err := prepareAuth(auth)
	if err != nil {
		return err
	}
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(context.Background(), true, func(state storageState, _ bool) (bool, error) {
		encoded, err := json.Marshal(copy)
		if err != nil {
			return false, fmt.Errorf("encode auth tokens: %w", err)
		}
		state["auth"] = encoded
		return true, nil
	})
}

// ClearAuth removes the stored tokens.
func (s *FileStorage) ClearAuth() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(context.Background(), false, func(state storageState, exists bool) (bool, error) {
		if !exists || isJSONNull(state["auth"]) {
			return false, nil
		}
		state["auth"] = json.RawMessage("null")
		return true, nil
	})
}

// GetPendingDeviceAuth returns the stored pending device authorization;
// expired entries are cleared and (nil, nil) is returned.
func (s *FileStorage) GetPendingDeviceAuth() (*PendingDeviceAuth, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	var pending *PendingDeviceAuth
	err := s.withState(context.Background(), false, func(state storageState, _ bool) (bool, error) {
		var err error
		pending, err = state.pending()
		if err != nil || pending == nil {
			return false, err
		}
		if time.Now().UnixMilli() >= pending.ExpiresAt {
			pending = nil
			state["pendingDeviceAuth"] = json.RawMessage("null")
			state.bumpDeviceAuthGeneration()
			return true, nil
		}
		return false, nil
	})
	return pending, err
}

// SetPendingDeviceAuth stores the pending device authorization.
func (s *FileStorage) SetPendingDeviceAuth(pending *PendingDeviceAuth) error {
	copy, err := preparePending(pending)
	if err != nil {
		return err
	}
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(context.Background(), true, func(state storageState, _ bool) (bool, error) {
		encoded, err := json.Marshal(copy)
		if err != nil {
			return false, fmt.Errorf("encode pending device auth: %w", err)
		}
		state["pendingDeviceAuth"] = encoded
		state.bumpDeviceAuthGeneration()
		return true, nil
	})
}

// ClearPendingDeviceAuth removes the stored pending device authorization.
func (s *FileStorage) ClearPendingDeviceAuth() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(context.Background(), false, func(state storageState, exists bool) (bool, error) {
		if !exists || isJSONNull(state["pendingDeviceAuth"]) {
			return false, nil
		}
		state["pendingDeviceAuth"] = json.RawMessage("null")
		state.bumpDeviceAuthGeneration()
		return true, nil
	})
}

// ClearAll removes both the stored tokens and any pending device
// authorization.
func (s *FileStorage) ClearAll() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	return s.withState(context.Background(), false, func(state storageState, exists bool) (bool, error) {
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

// Update performs a cross-instance, and on supported Unix platforms
// cross-process, atomic session transaction.
func (s *FileStorage) Update(ctx context.Context, update func(*AuthStorageState) error) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if update == nil {
		return fmt.Errorf("%w: storage update callback is required", ErrInvalidArgument)
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

// MemoryStorage is an in-memory AuthStorage for tests and ephemeral
// processes; nothing is persisted. The zero value is ready to use.
// MemoryStorage is safe for concurrent use.
type MemoryStorage struct {
	gate       storageGate
	auth       *AuthTokens
	pending    *PendingDeviceAuth
	generation uint64
}

// GetAuth returns the stored tokens, or (nil, nil) when not authenticated.
func (s *MemoryStorage) GetAuth() (*AuthTokens, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	return cloneAuth(s.auth), nil
}

// SetAuth stores the tokens, computing ExpiresAt from ExpiresIn when
// ExpiresAt is zero.
func (s *MemoryStorage) SetAuth(auth *AuthTokens) error {
	copy, err := prepareAuth(auth)
	if err != nil {
		return err
	}
	if s == nil {
		return invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	s.auth = copy
	return nil
}

// ClearAuth removes the stored tokens.
func (s *MemoryStorage) ClearAuth() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	s.auth = nil
	return nil
}

// GetPendingDeviceAuth returns the stored pending device authorization;
// expired entries are cleared and (nil, nil) is returned.
func (s *MemoryStorage) GetPendingDeviceAuth() (*PendingDeviceAuth, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	if s.pending != nil && time.Now().UnixMilli() >= s.pending.ExpiresAt {
		s.pending = nil
		s.generation = nextGeneration(s.generation)
	}
	return clonePending(s.pending), nil
}

// SetPendingDeviceAuth stores the pending device authorization.
func (s *MemoryStorage) SetPendingDeviceAuth(pending *PendingDeviceAuth) error {
	copy, err := preparePending(pending)
	if err != nil {
		return err
	}
	if s == nil {
		return invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	s.pending = copy
	s.generation = nextGeneration(s.generation)
	return nil
}

// ClearPendingDeviceAuth removes the stored pending device authorization.
func (s *MemoryStorage) ClearPendingDeviceAuth() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	s.pending = nil
	s.generation = nextGeneration(s.generation)
	return nil
}

// ClearAll removes both the stored tokens and any pending device
// authorization.
func (s *MemoryStorage) ClearAll() error {
	if s == nil {
		return invalidStorageReceiver()
	}
	_ = s.gate.lock(context.Background())
	defer s.gate.unlock()
	s.auth = nil
	s.pending = nil
	s.generation = nextGeneration(s.generation)
	return nil
}

// Update performs an atomic transaction shared by every Client using this
// MemoryStorage instance.
func (s *MemoryStorage) Update(ctx context.Context, update func(*AuthStorageState) error) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if update == nil {
		return fmt.Errorf("%w: storage update callback is required", ErrInvalidArgument)
	}
	if err := s.gate.lock(ctx); err != nil {
		return err
	}
	defer s.gate.unlock()
	state := &AuthStorageState{
		Auth:                 cloneAuth(s.auth),
		PendingDeviceAuth:    clonePending(s.pending),
		DeviceAuthGeneration: s.generation,
	}
	if err := update(state); err != nil {
		return err
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	auth, pending, err := prepareStorageSnapshot(state)
	if err != nil {
		return err
	}
	s.auth = auth
	s.pending = pending
	s.generation = state.DeviceAuthGeneration
	return nil
}

type storageState map[string]json.RawMessage

func (s *FileStorage) withState(ctx context.Context, createDirectory bool, update func(storageState, bool) (bool, error)) error {
	if err := s.gate.lock(ctx); err != nil {
		return err
	}
	defer s.gate.unlock()

	info, statErr := os.Lstat(s.path)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect auth storage file: %w", statErr)
	}
	if exists && !info.Mode().IsRegular() {
		return fmt.Errorf("auth storage path is not a regular file: %s", s.path)
	}
	if !exists && !createDirectory {
		changed, err := update(newStorageState(), false)
		if err != nil || !changed {
			return err
		}
		createDirectory = true
	}

	dir := filepath.Dir(s.path)
	if createDirectory {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create auth storage directory: %w", err)
		}
	}
	lock, err := acquireStorageLock(ctx, s.path+".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := contextFailure(ctx); err != nil {
		return err
	}

	state, exists, err := readStorageState(s.path)
	if err != nil {
		return err
	}
	changed, err := update(state, exists)
	if err != nil || !changed {
		return err
	}
	return writeStorageState(ctx, s.path, state, s.ops)
}

func newStorageState() storageState {
	return storageState{
		"auth":                 json.RawMessage("null"),
		"pendingDeviceAuth":    json.RawMessage("null"),
		"deviceAuthGeneration": json.RawMessage("0"),
	}
}

func readStorageState(path string) (storageState, bool, error) {
	file, err := openCredentialFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newStorageState(), false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open auth storage file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxAuthFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read auth storage file: %w", err)
	}
	if int64(len(data)) > maxAuthFileBytes {
		return nil, false, ErrStorageTooLarge
	}
	state, err := decodeStorageState(data)
	if err != nil {
		return nil, false, err
	}
	return state, true, nil
}

func decodeStorageState(data []byte) (storageState, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode auth storage file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, fmt.Errorf("decode auth storage file: %w", err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("decode auth storage file: top-level value must be an object")
	}
	var state storageState
	if err := json.Unmarshal(trimmed, &state); err != nil {
		return nil, fmt.Errorf("decode auth storage file: %w", err)
	}
	if state == nil {
		return nil, errors.New("decode auth storage file: top-level value must be an object")
	}
	if _, err := state.auth(); err != nil {
		return nil, err
	}
	if _, err := state.pending(); err != nil {
		return nil, err
	}
	if _, ok := state["auth"]; !ok {
		state["auth"] = json.RawMessage("null")
	}
	if _, ok := state["pendingDeviceAuth"]; !ok {
		state["pendingDeviceAuth"] = json.RawMessage("null")
	}
	if _, err := state.deviceAuthGeneration(); err != nil {
		return nil, err
	}
	if _, ok := state["deviceAuthGeneration"]; !ok {
		state["deviceAuthGeneration"] = json.RawMessage("0")
	}
	return state, nil
}

func (s storageState) snapshot() (*AuthStorageState, error) {
	auth, err := s.auth()
	if err != nil {
		return nil, err
	}
	pending, err := s.pending()
	if err != nil {
		return nil, err
	}
	generation, err := s.deviceAuthGeneration()
	if err != nil {
		return nil, err
	}
	return &AuthStorageState{Auth: auth, PendingDeviceAuth: pending, DeviceAuthGeneration: generation}, nil
}

func (s storageState) replaceSnapshot(state *AuthStorageState) error {
	auth, pending, err := prepareStorageSnapshot(state)
	if err != nil {
		return err
	}
	if auth == nil {
		s["auth"] = json.RawMessage("null")
	} else {
		s["auth"], err = json.Marshal(auth)
		if err != nil {
			return fmt.Errorf("encode auth tokens: %w", err)
		}
	}
	if pending == nil {
		s["pendingDeviceAuth"] = json.RawMessage("null")
	} else {
		s["pendingDeviceAuth"], err = json.Marshal(pending)
		if err != nil {
			return fmt.Errorf("encode pending device auth: %w", err)
		}
	}
	s["deviceAuthGeneration"] = json.RawMessage(fmt.Sprintf("%d", state.DeviceAuthGeneration))
	return nil
}

func (s storageState) deviceAuthGeneration() (uint64, error) {
	raw, ok := s["deviceAuthGeneration"]
	if !ok || isJSONNull(raw) {
		return 0, nil
	}
	var generation uint64
	if err := json.Unmarshal(raw, &generation); err != nil {
		return 0, fmt.Errorf("decode auth storage field deviceAuthGeneration: %w", err)
	}
	return generation, nil
}

func (s storageState) bumpDeviceAuthGeneration() {
	generation, err := s.deviceAuthGeneration()
	if err != nil {
		// Existing state is validated before update callbacks reach this point.
		return
	}
	s["deviceAuthGeneration"] = json.RawMessage(fmt.Sprintf("%d", nextGeneration(generation)))
}

func nextGeneration(current uint64) uint64 {
	if current == math.MaxUint64 {
		return 1
	}
	return current + 1
}

func prepareStorageSnapshot(state *AuthStorageState) (*AuthTokens, *PendingDeviceAuth, error) {
	if state == nil {
		return nil, nil, fmt.Errorf("%w: auth storage state is required", ErrInvalidArgument)
	}
	var auth *AuthTokens
	var pending *PendingDeviceAuth
	var err error
	if state.Auth != nil {
		auth, err = prepareAuth(state.Auth)
		if err != nil {
			return nil, nil, err
		}
	}
	if state.PendingDeviceAuth != nil {
		pending, err = preparePending(state.PendingDeviceAuth)
		if err != nil {
			return nil, nil, err
		}
	}
	return auth, pending, nil
}

func (s storageState) auth() (*AuthTokens, error) {
	raw, ok := s["auth"]
	if !ok || isJSONNull(raw) {
		return nil, nil
	}
	var auth AuthTokens
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("decode auth storage field auth: %w", err)
	}
	if _, err := validateAuth(&auth); err != nil {
		return nil, fmt.Errorf("decode auth storage field auth: %w", err)
	}
	return &auth, nil
}

func (s storageState) pending() (*PendingDeviceAuth, error) {
	raw, ok := s["pendingDeviceAuth"]
	if !ok || isJSONNull(raw) {
		return nil, nil
	}
	var pending PendingDeviceAuth
	if err := json.Unmarshal(raw, &pending); err != nil {
		return nil, fmt.Errorf("decode auth storage field pendingDeviceAuth: %w", err)
	}
	if err := validatePending(&pending); err != nil {
		return nil, fmt.Errorf("decode auth storage field pendingDeviceAuth: %w", err)
	}
	return &pending, nil
}

func writeStorageState(ctx context.Context, path string, state storageState, ops storageFileOps) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	if err := validateStorageDestination(path); err != nil {
		return err
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	data, err := ops.marshal(state)
	if err != nil {
		return fmt.Errorf("encode auth storage file: %w", err)
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := ops.createTemp(dir, ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary auth storage file: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	cleanup := func(cause error) error {
		// A failed Close does not offer a portable guarantee about descriptor
		// state. Close the concrete file again before removal so Windows cannot
		// retain a credential-bearing temp merely because the injected/OS close
		// path left the handle live.
		_ = temp.Close()
		removeErr := os.Remove(tempPath)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			removeTemp = false
			return cause
		}
		return errors.Join(cause, fmt.Errorf("remove temporary auth storage file: %w", removeErr))
	}
	fail := func(operation string, cause error) error {
		_ = ops.close(temp)
		return cleanup(fmt.Errorf("%s auth storage file: %w", operation, cause))
	}
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if err := temp.Chmod(0o600); err != nil {
		return fail("secure temporary", err)
	}
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if _, err := ops.write(temp, data); err != nil {
		return fail("write temporary", err)
	}
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if err := ops.sync(temp); err != nil {
		return fail("sync temporary", err)
	}
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if err := ops.close(temp); err != nil {
		return cleanup(fmt.Errorf("close temporary auth storage file: %w", err))
	}
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if err := validateStorageDestination(path); err != nil {
		return cleanup(err)
	}
	// This is the final cancellation checkpoint. Once rename begins, the new
	// file may be committed; cancellation after that point cannot truthfully be
	// reported as an uncommitted transaction and must not mask durability
	// errors from the directory sync.
	if err := contextFailure(ctx); err != nil {
		return cleanup(err)
	}
	if err := ops.rename(tempPath, path); err != nil {
		return cleanup(fmt.Errorf("replace auth storage file: %w", err))
	}
	removeTemp = false
	if err := ops.syncDirectory(dir); err != nil {
		return fmt.Errorf("sync auth storage directory: %w", err)
	}
	return nil
}

func validateStorageDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect auth storage file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("auth storage path is not a regular file: %s", path)
	}
	return nil
}

func syncDirectory(path string) error {
	if err := syncDirectoryRaw(path); err != nil {
		return fmt.Errorf("sync auth storage directory: %w", err)
	}
	return nil
}

func prepareAuth(auth *AuthTokens) (*AuthTokens, error) {
	copy, err := validateAuth(auth)
	if err != nil {
		return nil, err
	}
	if copy.ExpiresAt == 0 {
		now := time.Now().UnixMilli()
		if copy.ExpiresIn > (math.MaxInt64-now)/1000 {
			return nil, fmt.Errorf("%w: auth token expiry overflows epoch milliseconds", ErrInvalidArgument)
		}
		copy.ExpiresAt = now + copy.ExpiresIn*1000
	}
	return copy, nil
}

func validateAuth(auth *AuthTokens) (*AuthTokens, error) {
	if auth == nil {
		return nil, fmt.Errorf("%w: auth tokens are required", ErrInvalidArgument)
	}
	if auth.AccessToken == "" || auth.RefreshToken == "" || auth.TokenType == "" || auth.ExpiresIn <= 0 || auth.ExpiresAt < 0 {
		return nil, fmt.Errorf("%w: auth tokens contain missing or invalid fields", ErrInvalidArgument)
	}
	return cloneAuth(auth), nil
}

func preparePending(pending *PendingDeviceAuth) (*PendingDeviceAuth, error) {
	if err := validatePending(pending); err != nil {
		return nil, err
	}
	return clonePending(pending), nil
}

func validatePending(pending *PendingDeviceAuth) error {
	if pending == nil {
		return fmt.Errorf("%w: pending device auth is required", ErrInvalidArgument)
	}
	if pending.DeviceCode == "" || pending.Interval <= 0 || pending.ExpiresAt <= 0 || pending.VerificationURL == "" || pending.Phrase == "" {
		return fmt.Errorf("%w: pending device auth contains missing or invalid fields", ErrInvalidArgument)
	}
	return nil
}

func cloneAuth(auth *AuthTokens) *AuthTokens {
	if auth == nil {
		return nil
	}
	copy := *auth
	return &copy
}

func clonePending(pending *PendingDeviceAuth) *PendingDeviceAuth {
	if pending == nil {
		return nil
	}
	copy := *pending
	return &copy
}

func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func invalidStorageReceiver() error {
	return fmt.Errorf("%w: auth storage is nil", ErrInvalidArgument)
}
