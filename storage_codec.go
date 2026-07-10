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
	"time"
)

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

func sameAuthTokens(a, b *AuthTokens) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
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
