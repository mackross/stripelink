package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthStorageTransactIsAtomicAndContextAware(t *testing.T) {
	for name, pair := range map[string]func(*testing.T) (AuthStorage, AuthStorage){
		"memory": func(t *testing.T) (AuthStorage, AuthStorage) {
			storage := &MemoryStorage{}
			return storage, storage
		},
		"file": func(t *testing.T) (AuthStorage, AuthStorage) {
			path := filepath.Join(t.TempDir(), "auth.json")
			a, _ := NewFileStorage(path)
			b, _ := NewFileStorage(path)
			return a, b
		},
	} {
		t.Run(name, func(t *testing.T) {
			writer, reader := pair(t)
			if err := storePendingDeviceAuth(writer, validPending()); err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			writeDone := make(chan error, 1)
			go func() {
				writeDone <- writer.Transact(context.Background(), func(state *AuthStorageState) error {
					state.Auth = validAuth()
					state.PendingDeviceAuth = nil
					close(entered)
					<-release
					return nil
				})
			}()
			<-entered

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			called := false
			err := reader.Transact(ctx, func(*AuthStorageState) error {
				called = true
				return nil
			})
			if !errors.Is(err, context.Canceled) || called {
				t.Fatalf("canceled Transact = %v, called=%v", err, called)
			}

			close(release)
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			state, stateErr := reader.Load(t.Context())
			auth, pending := state.Auth, state.PendingDeviceAuth
			if stateErr != nil || auth == nil || pending != nil {
				t.Fatalf("atomic state auth=%#v pending=%#v error=%v", auth, pending, stateErr)
			}
		})
	}
}

func TestAuthStorageOperationsValidateContextAndCallback(t *testing.T) {
	for name, storage := range storageImplementations(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := storage.Load(nilContext()); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("Load(nil) error = %v", err)
			}
			if err := storage.Transact(t.Context(), nil); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("Transact(nil callback) error = %v", err)
			}
			if err := storage.Clear(nilContext()); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("Clear(nil) error = %v", err)
			}
		})
	}

	file, err := NewFileStorage(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Delete(nilContext()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Delete(nil) error = %v", err)
	}
}

func TestFileStorageDeleteHonorsCancellationWhileWaitingForLock(t *testing.T) {
	storage, err := NewFileStorage(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.gate.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer storage.gate.unlock()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- storage.Delete(ctx) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete error = %v, want context cancellation", err)
	}
}

func validAuth() *AuthTokens {
	return &AuthTokens{
		AccessToken:  "at_secret",
		RefreshToken: "rt_secret",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}
}

func validPending() *PendingDeviceAuth {
	return &PendingDeviceAuth{
		DeviceCode:      "dc_secret",
		Interval:        5,
		ExpiresAt:       time.Now().Add(time.Hour).UnixMilli(),
		VerificationURL: "https://login.link.com/device",
		Phrase:          "quiet-copper",
	}
}

func TestPendingDeviceAuthFormattingRedactsCredentials(t *testing.T) {
	const secret = "pending_financial_secret"
	value := PendingDeviceAuth{DeviceCode: secret, VerificationURL: secret, Phrase: secret}
	for _, candidate := range []any{value, &value, AuthStorageState{Auth: &AuthTokens{AccessToken: secret}, PendingDeviceAuth: &value}} {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, candidate)
			if strings.Contains(got, secret) || !strings.Contains(got, "<redacted>") {
				t.Errorf("%T with %s formatted unsafely: %s", candidate, format, got)
			}
		}
	}
}

func storageImplementations(t *testing.T) map[string]AuthStorage {
	t.Helper()
	file, err := NewFileStorage(filepath.Join(t.TempDir(), "nested", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]AuthStorage{
		"memory": new(MemoryStorage),
		"file":   file,
	}
}

func TestAuthStorageValueSemantics(t *testing.T) {
	for name, storage := range storageImplementations(t) {
		t.Run(name, func(t *testing.T) {
			auth := validAuth()
			if err := storeAuth(storage, auth); err != nil {
				t.Fatal(err)
			}
			auth.AccessToken = "mutated"
			got, err := loadStoredAuth(storage)
			if err != nil {
				t.Fatal(err)
			}
			if got.AccessToken != "at_secret" || got.ExpiresAt <= time.Now().UnixMilli() {
				t.Fatalf("stored auth = %#v", got)
			}
			got.AccessToken = "mutated-again"
			got, _ = loadStoredAuth(storage)
			if got.AccessToken != "at_secret" {
				t.Fatalf("Load leaked storage-owned auth: %#v", got)
			}

			pending := validPending()
			if err := storePendingDeviceAuth(storage, pending); err != nil {
				t.Fatal(err)
			}
			pending.DeviceCode = "mutated"
			gotPending, err := loadStoredPendingDeviceAuth(storage)
			if err != nil {
				t.Fatal(err)
			}
			if gotPending.DeviceCode != "dc_secret" {
				t.Fatalf("stored pending = %#v", gotPending)
			}
			gotPending.DeviceCode = "mutated-again"
			gotPending, _ = loadStoredPendingDeviceAuth(storage)
			if gotPending.DeviceCode != "dc_secret" {
				t.Fatalf("Load leaked storage-owned pending auth: %#v", gotPending)
			}

			expired := validPending()
			expired.ExpiresAt = time.Now().Add(-time.Millisecond).UnixMilli()
			if err := storePendingDeviceAuth(storage, expired); err != nil {
				t.Fatal(err)
			}
			gotPending, err = loadStoredPendingDeviceAuth(storage)
			if err != nil || gotPending == nil || gotPending.ExpiresAt != expired.ExpiresAt {
				t.Fatalf("stored expired pending = %#v, %v", gotPending, err)
			}
		})
	}
}

func TestAuthStorageRejectsInvalidInputWithoutMutation(t *testing.T) {
	for name, storage := range storageImplementations(t) {
		t.Run(name, func(t *testing.T) {
			original := validAuth()
			original.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
			if err := storeAuth(storage, original); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []*AuthTokens{{}, {AccessToken: "at", RefreshToken: "rt", ExpiresIn: -1, TokenType: "Bearer"}} {
				if err := storeAuth(storage, invalid); !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("store invalid auth %#v error = %v", invalid, err)
				}
			}
			got, err := loadStoredAuth(storage)
			if err != nil || *got != *original {
				t.Fatalf("state changed: %#v, %v", got, err)
			}
			if err := storePendingDeviceAuth(storage, nil); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("store nil pending auth error = %v", err)
			}
		})
	}
}

func TestAuthStorageClearOperations(t *testing.T) {
	for name, storage := range storageImplementations(t) {
		t.Run(name, func(t *testing.T) {
			if err := storeAuth(storage, validAuth()); err != nil {
				t.Fatal(err)
			}
			if err := storePendingDeviceAuth(storage, validPending()); err != nil {
				t.Fatal(err)
			}
			if err := clearStoredAuth(storage); err != nil {
				t.Fatal(err)
			}
			if err := clearStoredAuth(storage); err != nil {
				t.Fatal(err)
			}
			if auth, _ := loadStoredAuth(storage); auth != nil {
				t.Fatalf("auth not cleared: %#v", auth)
			}
			if pending, _ := loadStoredPendingDeviceAuth(storage); pending == nil {
				t.Fatal("clearing auth also cleared pending state")
			}
			if err := clearStoredPendingDeviceAuth(storage); err != nil {
				t.Fatal(err)
			}
			if err := storeAuth(storage, validAuth()); err != nil {
				t.Fatal(err)
			}
			if err := storePendingDeviceAuth(storage, validPending()); err != nil {
				t.Fatal(err)
			}
			if err := clearStoredPendingDeviceAuth(storage); err != nil {
				t.Fatal(err)
			}
			if auth, _ := loadStoredAuth(storage); auth == nil {
				t.Fatal("clearing pending state also cleared auth")
			}
			if err := storage.Clear(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := storage.Clear(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFileStorageSchemaPermissionsAndUnknownState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private", "nested")
	path := filepath.Join(dir, "auth.json")
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if storage.Path() != path {
		t.Fatalf("Path = %q", storage.Path())
	}
	if err := storeAuth(storage, validAuth()); err != nil {
		t.Fatal(err)
	}
	assertMode(t, dir, 0o700)
	assertMode(t, path, 0o600)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if _, ok := state["pendingDeviceAuth"]; !ok {
		t.Fatalf("missing JS schema key: %s", data)
	}
	if !strings.Contains(string(state["auth"]), `"access_token"`) || strings.Contains(string(data), `"AccessToken"`) {
		t.Fatalf("wrong JS field schema: %s", data)
	}

	fixture := fmt.Sprintf(`{"auth":%s,"pendingDeviceAuth":null,"future":{"kept":true}}`, state["auth"])
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStoredAuth(storage); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0o600)
	if err := storePendingDeviceAuth(storage, validPending()); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), `"future"`) || !strings.Contains(string(data), `"kept":true`) {
		t.Fatalf("unknown state lost: %s", data)
	}
}

func TestFileStorageRejectsUnsafeOrInvalidFiles(t *testing.T) {
	for name, contents := range map[string][]byte{
		"malformed":       []byte(`{"auth":`),
		"trailing value":  []byte(`{} {}`),
		"top-level null":  []byte(`null`),
		"top-level array": []byte(`[]`),
		"wrong auth type": []byte(`{"auth":true,"pendingDeviceAuth":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth.json")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			storage, _ := NewFileStorage(path)
			if _, err := loadStoredAuth(storage); err == nil {
				t.Fatal("expected explicit decode error")
			}
		})
	}

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "auth.json")
		original := make([]byte, maxAuthFileBytes+1)
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		storage, _ := NewFileStorage(path)
		if _, err := loadStoredAuth(storage); !errors.Is(err, ErrStorageTooLarge) {
			t.Fatalf("error = %v", err)
		}
		if err := storeAuth(storage, validAuth()); !errors.Is(err, ErrStorageTooLarge) {
			t.Fatalf("Transact error = %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("oversized storage changed: len=%d, %v", len(got), err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		storage, _ := NewFileStorage(t.TempDir())
		if _, err := loadStoredAuth(storage); err == nil {
			t.Fatal("expected non-regular-file error")
		}
	})

	t.Run("untraversable path", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, []byte("ordinary file"), 0o600); err != nil {
			t.Fatal(err)
		}
		storage, _ := NewFileStorage(filepath.Join(parent, "auth.json"))
		if _, err := loadStoredAuth(storage); err == nil || !strings.Contains(err.Error(), "inspect auth storage file") {
			t.Fatalf("Load error = %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("symlink", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			link := filepath.Join(dir, "auth.json")
			if err := os.WriteFile(target, []byte(`{"auth":null,"pendingDeviceAuth":null}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			storage, _ := NewFileStorage(link)
			if _, err := loadStoredAuth(storage); err == nil {
				t.Fatal("expected symlink rejection")
			}
			if err := deleteStoredFile(storage); err == nil {
				t.Fatal("expected Delete symlink rejection")
			}
			if err := clearStoredState(storage); err == nil {
				t.Fatal("expected Clear symlink rejection")
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("symlink target touched: %v", err)
			}
		})

		t.Run("lock symlink", func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("do not touch"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path+".lock"); err != nil {
				t.Fatal(err)
			}
			storage, _ := NewFileStorage(path)
			if err := storeAuth(storage, validAuth()); err == nil {
				t.Fatal("expected lock symlink rejection")
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "do not touch" {
				t.Fatalf("lock symlink target touched: %q, %v", got, err)
			}
		})
	}
}

func TestFileStorageFailedWritePreservesLastValidState(t *testing.T) {
	if !crossProcessStorageLockSupported {
		t.Skip("POSIX directory permissions are required")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	storage, _ := NewFileStorage(path)
	original := validAuth()
	original.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
	if err := storeAuth(storage, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	replacement := validAuth()
	replacement.AccessToken = "at_replacement"
	if err := storeAuth(storage, replacement); err == nil {
		t.Fatal("expected write failure in non-writable directory")
	}
	got, err := loadStoredAuth(storage)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *original {
		t.Fatalf("failed write changed state: %#v", got)
	}
}

func TestFileStorageAtomicWriteFaultBoundaries(t *testing.T) {
	injected := errors.New("injected storage fault")
	tests := []struct {
		name          string
		wantOperation string
		newCommitted  bool
		inject        func(*storageFileOps, *testing.T)
	}{
		{
			name:          "encode",
			wantOperation: "encode auth storage file",
			inject: func(ops *storageFileOps, _ *testing.T) {
				ops.marshal = func(any) ([]byte, error) { return nil, injected }
			},
		},
		{
			name:          "temporary create",
			wantOperation: "create temporary auth storage file",
			inject: func(ops *storageFileOps, _ *testing.T) {
				ops.createTemp = func(string, string) (*os.File, error) { return nil, injected }
			},
		},
		{
			name:          "temporary write",
			wantOperation: "write temporary auth storage file",
			inject: func(ops *storageFileOps, _ *testing.T) {
				ops.write = func(file *os.File, data []byte) (int, error) {
					n, _ := file.Write(data[:len(data)/2])
					return n, injected
				}
			},
		},
		{
			name:          "temporary sync",
			wantOperation: "sync temporary auth storage file",
			inject: func(ops *storageFileOps, t *testing.T) {
				ops.sync = func(file *os.File) error {
					assertMode(t, file.Name(), 0o600)
					return injected
				}
			},
		},
		{
			name:          "temporary close",
			wantOperation: "close temporary auth storage file",
			inject: func(ops *storageFileOps, _ *testing.T) {
				// Model the most conservative close failure: the hook reports an
				// error without closing the descriptor. Production cleanup must
				// still close it before removing the credential-bearing temp file.
				ops.close = func(*os.File) error { return injected }
			},
		},
		{
			name:          "rename",
			wantOperation: "replace auth storage file",
			inject: func(ops *storageFileOps, _ *testing.T) {
				ops.rename = func(string, string) error { return injected }
			},
		},
		{
			name:          "directory sync",
			wantOperation: "sync auth storage directory",
			newCommitted:  true,
			inject: func(ops *storageFileOps, _ *testing.T) {
				ops.syncDirectory = func(string) error { return injected }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			storage, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			original := validAuth()
			original.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
			if err := storeAuth(storage, original); err != nil {
				t.Fatal(err)
			}

			test.inject(&storage.ops, t)
			replacement := validAuth()
			replacement.AccessToken = "at_replacement"
			replacement.ExpiresAt = original.ExpiresAt + 1
			err = storeAuth(storage, replacement)
			if !errors.Is(err, injected) {
				t.Fatalf("error = %v, want injected cause", err)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantOperation) {
				t.Fatalf("error = %v, want operation %q", err, test.wantOperation)
			}

			storage.ops = defaultStorageFileOps()
			got, err := loadStoredAuth(storage)
			if err != nil {
				t.Fatalf("last valid credentials unreadable: %v", err)
			}
			want := original
			if test.newCommitted {
				want = replacement
			}
			if *got != *want {
				t.Fatalf("stored auth = %#v, want %#v", got, want)
			}
			assertMode(t, path, 0o600)
			temps, err := filepath.Glob(filepath.Join(dir, ".auth-*.tmp"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temps) != 0 {
				t.Fatalf("credential-bearing temporary files remain: %v", temps)
			}
		})
	}
}

func TestFileStorageTransactCancellationBeforeCommit(t *testing.T) {
	for _, boundary := range []string{"temporary write", "temporary sync"} {
		t.Run(boundary, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			storage, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			original := validAuth()
			original.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
			if err := storeAuth(storage, original); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch boundary {
			case "temporary write":
				write := storage.ops.write
				storage.ops.write = func(file *os.File, data []byte) (int, error) {
					n, err := write(file, data)
					cancel()
					return n, err
				}
			case "temporary sync":
				syncFile := storage.ops.sync
				storage.ops.sync = func(file *os.File) error {
					err := syncFile(file)
					cancel()
					return err
				}
			}

			replacement := validAuth()
			replacement.AccessToken = "at_must_not_persist"
			replacement.ExpiresAt = original.ExpiresAt + 1
			err = storage.Transact(ctx, func(state *AuthStorageState) error {
				state.Auth = replacement
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Transact error = %v, want context cancellation", err)
			}

			storage.ops = defaultStorageFileOps()
			reader, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			for range 100 {
				runtime.Gosched()
				got, err := loadStoredAuth(reader)
				if err != nil {
					t.Fatalf("last valid credentials unreadable: %v", err)
				}
				if *got != *original {
					t.Fatalf("credentials persisted after cancellation: %#v", got)
				}
			}
			temps, err := filepath.Glob(filepath.Join(dir, ".auth-*.tmp"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temps) != 0 {
				t.Fatalf("credential-bearing temporary files remain: %v", temps)
			}
		})
	}
}

func TestFileStorageTransactCancellationAfterRenameReportsDurabilityError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeAuth(storage, validAuth()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	rename := storage.ops.rename
	storage.ops.rename = func(oldPath, newPath string) error {
		if err := rename(oldPath, newPath); err != nil {
			return err
		}
		cancel()
		return nil
	}
	durabilityFailure := errors.New("injected directory durability failure")
	storage.ops.syncDirectory = func(string) error { return durabilityFailure }
	replacement := validAuth()
	replacement.AccessToken = "at_committed"
	err = storage.Transact(ctx, func(state *AuthStorageState) error {
		state.Auth = replacement
		return nil
	})
	if !errors.Is(err, durabilityFailure) {
		t.Fatalf("Transact error = %v, want durability failure", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("post-commit cancellation masked commit state: %v", err)
	}

	reader, _ := NewFileStorage(path)
	got, err := loadStoredAuth(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != replacement.AccessToken {
		t.Fatalf("committed credentials = %#v", got)
	}
}

func TestFileStorageMissingAndDeleteAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	storage, _ := NewFileStorage(path)
	if auth, err := loadStoredAuth(storage); err != nil || auth != nil {
		t.Fatalf("missing auth = %#v, %v", auth, err)
	}
	if err := deleteStoredFile(storage); err != nil {
		t.Fatal(err)
	}
	if err := storeAuth(storage, validAuth()); err != nil {
		t.Fatal(err)
	}
	if err := deleteStoredFile(storage); err != nil {
		t.Fatal(err)
	}
	if err := deleteStoredFile(storage); err != nil {
		t.Fatal(err)
	}
}

func TestFileStorageCoordinatesInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	a, _ := NewFileStorage(path)
	b, _ := NewFileStorage(path)
	for range 20 {
		if err := clearStoredState(a); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() { <-start; errs <- storeAuth(a, validAuth()) }()
		go func() { <-start; errs <- storePendingDeviceAuth(b, validPending()) }()
		close(start)
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		auth, authErr := loadStoredAuth(a)
		pending, pendingErr := loadStoredPendingDeviceAuth(b)
		if authErr != nil || pendingErr != nil || auth == nil || pending == nil {
			t.Fatalf("lost update: auth=%#v/%v pending=%#v/%v", auth, authErr, pending, pendingErr)
		}
	}
}

func TestFileStorageCoordinatesProcesses(t *testing.T) {
	if !crossProcessStorageLockSupported {
		t.Skip("cross-process advisory locking is unavailable")
	}
	if role := os.Getenv("STRIPELINK_STORAGE_HELPER_ROLE"); role != "" {
		path := os.Getenv("STRIPELINK_STORAGE_HELPER_PATH")
		storage, err := NewFileStorage(path)
		if err != nil {
			t.Fatal(err)
		}
		for range 50 {
			switch role {
			case "auth":
				err = storeAuth(storage, validAuth())
			case "pending":
				err = storePendingDeviceAuth(storage, validPending())
			default:
				t.Fatalf("unknown helper role %q", role)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	commands := make([]*exec.Cmd, 0, 2)
	outputs := make([]bytes.Buffer, 2)
	for i, role := range []string{"auth", "pending"} {
		command := exec.Command(executable, "-test.run=^TestFileStorageCoordinatesProcesses$")
		command.Env = append(os.Environ(),
			"STRIPELINK_STORAGE_HELPER_ROLE="+role,
			"STRIPELINK_STORAGE_HELPER_PATH="+path,
		)
		command.Stdout = &outputs[i]
		command.Stderr = &outputs[i]
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
	}
	for i, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("storage helper failed: %v\n%s", err, outputs[i].Bytes())
		}
	}
	storage, _ := NewFileStorage(path)
	auth, authErr := loadStoredAuth(storage)
	pending, pendingErr := loadStoredPendingDeviceAuth(storage)
	if authErr != nil || pendingErr != nil || auth == nil || pending == nil {
		t.Fatalf("lost cross-process update: auth=%#v/%v pending=%#v/%v", auth, authErr, pending, pendingErr)
	}
}

func TestFileStorageTransactCoordinatesProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cross-process advisory locking is unavailable")
	}
	if os.Getenv("STRIPELINK_UPDATE_HELPER") != "" {
		storage, err := NewFileStorage(os.Getenv("STRIPELINK_STORAGE_HELPER_PATH"))
		if err != nil {
			t.Fatal(err)
		}
		for range 25 {
			err := storage.Transact(t.Context(), func(state *AuthStorageState) error {
				value, err := strconv.Atoi(state.Auth.AccessToken)
				if err != nil {
					return err
				}
				state.Auth.AccessToken = strconv.Itoa(value + 1)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	path := filepath.Join(t.TempDir(), "auth.json")
	storage, _ := NewFileStorage(path)
	initial := validAuth()
	initial.AccessToken = "0"
	if err := storeAuth(storage, initial); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]*exec.Cmd, 2)
	outputs := make([]bytes.Buffer, 2)
	for i := range commands {
		commands[i] = exec.Command(executable, "-test.run=^TestFileStorageTransactCoordinatesProcesses$")
		commands[i].Env = append(os.Environ(), "STRIPELINK_UPDATE_HELPER=1", "STRIPELINK_STORAGE_HELPER_PATH="+path)
		commands[i].Stdout = &outputs[i]
		commands[i].Stderr = &outputs[i]
		if err := commands[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("update helper failed: %v\n%s", err, outputs[i].Bytes())
		}
	}
	auth, err := loadStoredAuth(storage)
	if err != nil || auth == nil || auth.AccessToken != "50" {
		t.Fatalf("transaction result = %#v, %v", auth, err)
	}
}

func TestMemoryStorageConcurrentAccess(t *testing.T) {
	var storage MemoryStorage
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); _ = storeAuth(&storage, validAuth()); _, _ = loadStoredAuth(&storage) }()
		go func() {
			defer wg.Done()
			_ = storePendingDeviceAuth(&storage, validPending())
			_, _ = loadStoredPendingDeviceAuth(&storage)
		}()
	}
	wg.Wait()
}

func TestNewFileStorageDefaultPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", root)
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := NewFileStorage("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configRoot, "stripelink", "auth.json")
	if storage.Path() != want {
		t.Fatalf("Path = %q, want %q", storage.Path(), want)
	}
}

func TestZeroOptionClientReadsExactDefaultPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv(envAuthBaseURL, "")
	t.Setenv(envAPIBaseURL, "")
	t.Setenv(envHTTPProxy, "")
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(configRoot, "stripelink", "auth.json")
	seed, err := NewFileStorage(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeAuth(seed, storedToken("seeded-default", "seeded-refresh", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	file, ok := client.Auth.c.storage.(*FileStorage)
	if !ok {
		t.Fatalf("resolved storage = %T, want *FileStorage", client.Auth.c.storage)
	}
	if file.Path() != wantPath {
		t.Fatalf("resolved storage path = %q, want %q", file.Path(), wantPath)
	}
	token, err := client.Auth.c.getAccessToken(t.Context(), AccessTokenRequest{})
	if err != nil || token != "seeded-default" {
		t.Fatalf("seeded token = %q, %v", token, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != want {
		t.Fatalf("%s mode = %#o, want %#o", path, info.Mode().Perm(), want)
	}
}

func FuzzStorageStateDecode(f *testing.F) {
	f.Add([]byte(`{"auth":null,"pendingDeviceAuth":null}`))
	f.Add([]byte(`{"auth":{"access_token":"at","refresh_token":"rt","expires_in":1,"token_type":"Bearer","expires_at":1},"pendingDeviceAuth":null}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeStorageState(data)
	})
}
