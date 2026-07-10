package stripelink

import (
	"context"
	"fmt"
)

// MemoryStorage is an in-memory AuthStorage for tests and ephemeral
// processes; nothing is persisted. The zero value is ready to use.
// MemoryStorage is safe for concurrent use.
type MemoryStorage struct {
	gate       storageGate
	auth       *AuthTokens
	pending    *PendingDeviceAuth
	generation uint64
}

// Load returns a defensive copy of the complete stored auth state.
func (s *MemoryStorage) Load(ctx context.Context) (*AuthStorageState, error) {
	if s == nil {
		return nil, invalidStorageReceiver()
	}
	if err := s.gate.lock(ctx); err != nil {
		return nil, err
	}
	defer s.gate.unlock()
	return &AuthStorageState{
		Auth:                 cloneAuth(s.auth),
		PendingDeviceAuth:    clonePending(s.pending),
		DeviceAuthGeneration: s.generation,
	}, nil
}

// Transact performs an atomic transaction shared by every Client using this
// MemoryStorage instance.
func (s *MemoryStorage) Transact(ctx context.Context, update func(*AuthStorageState) error) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if update == nil {
		return fmt.Errorf("%w: storage transaction callback is required", ErrInvalidArgument)
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

// Clear atomically removes all stored auth and pending device-flow state.
func (s *MemoryStorage) Clear(ctx context.Context) error {
	if s == nil {
		return invalidStorageReceiver()
	}
	if err := s.gate.lock(ctx); err != nil {
		return err
	}
	defer s.gate.unlock()
	s.auth = nil
	s.pending = nil
	s.generation = nextGeneration(s.generation)
	return nil
}
