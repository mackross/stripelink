package stripelink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const tokenExpirySkew = 60 * time.Second

// tokenProvider is the storage-backed, auto-refreshing access-token source
// that NewClient wires as the default AccessTokenFunc when neither
// Options.AccessToken nor Options.GetAccessToken is set (GUIDANCE §5.6,
// §6.2 deviation #8 — in JS this logic lives in the CLI). It returns the
// stored access token while valid and, on forceRefresh or expiry (using
// expires_at minus a small skew), calls AuthResource.RefreshToken and
// persists the result.
//
// Refresh is single-flight: under concurrent demand exactly one RefreshToken
// call happens and the others wait for and reuse its result, because refresh
// tokens may be single-use server-side (GUIDANCE §7).
type tokenProvider struct {
	storage AuthStorage
	auth    *AuthResource

	// decision serializes the gap between reading storage and publishing a new
	// refreshCall. It is distinct from mu so waiter cancellation remains able
	// to update an in-flight call while its storage transaction is on the wire.
	decision storageGate
	mu       sync.Mutex
	// inflight is non-nil while a refresh is running; waiters block on done
	// and then read tokens/err. It is the hand-rolled single-flight result
	// share (GUIDANCE §7) — no x/sync dependency.
	inflight *refreshCall
}

// refreshCall carries the shared result of one in-flight token refresh.
type refreshCall struct {
	done   chan struct{} // closed when the refresh completes
	cancel context.CancelFunc

	// waiters is protected by tokenProvider.mu. When it reaches zero before
	// completion, the call is detached and canceled so it cannot later persist
	// credentials after every interested caller has returned.
	waiters int
	tokens  *AuthTokens
	err     error
}

// token implements AccessTokenFunc on top of storage and the auth resource.
// It returns ErrNotAuthenticated when storage holds no tokens. For a forced
// refresh it compares request.RejectedToken with the currently stored access
// token; a mismatch means another caller already refreshed this generation,
// so it returns the stored token without refreshing again. Each waiter may
// stop waiting when its own context is canceled. Shared work continues while
// at least one waiter remains and is canceled once the final waiter leaves.
func (p *tokenProvider) token(ctx context.Context, request AccessTokenRequest) (string, error) {
	if err := requireContext(ctx); err != nil {
		return "", err
	}
	if p.storage == nil || p.auth == nil {
		return "", ErrNotAuthenticated
	}

	// Join local shared work before touching storage. A refresh transaction can
	// deliberately hold the storage lock across the network exchange; trying to
	// read first would strand same-provider callers behind that lock instead of
	// letting them share its result.
	p.mu.Lock()
	if call := p.inflight; call != nil {
		call.waiters++
		p.mu.Unlock()
		return p.waitForRefresh(ctx, call)
	}
	p.mu.Unlock()
	if err := p.decision.lock(ctx); err != nil {
		return "", err
	}

	// A caller may have published a refresh while this caller waited to make
	// the next token decision.
	p.mu.Lock()
	if call := p.inflight; call != nil {
		call.waiters++
		p.mu.Unlock()
		p.decision.unlock()
		return p.waitForRefresh(ctx, call)
	}
	p.mu.Unlock()

	var stored *AuthTokens
	err := p.storage.Update(ctx, func(state *AuthStorageState) error {
		stored = cloneAuth(state.Auth)
		return nil
	})
	if err != nil {
		p.decision.unlock()
		return "", fmt.Errorf("stripelink: load authentication: %w", err)
	}

	p.mu.Lock()
	if call := p.inflight; call != nil {
		call.waiters++
		p.mu.Unlock()
		p.decision.unlock()
		return p.waitForRefresh(ctx, call)
	}
	if stored == nil || stored.AccessToken == "" {
		p.mu.Unlock()
		p.decision.unlock()
		return "", ErrNotAuthenticated
	}

	// A force-refresh for an already-replaced token is stale. Returning the
	// current generation prevents a delayed 401 from rotating a single-use
	// refresh token for a second time.
	if request.ForceRefresh && request.RejectedToken != "" && request.RejectedToken != stored.AccessToken {
		token := stored.AccessToken
		p.mu.Unlock()
		p.decision.unlock()
		return token, nil
	}
	if !request.ForceRefresh && !tokenNeedsRefresh(stored, time.Now()) {
		token := stored.AccessToken
		p.mu.Unlock()
		p.decision.unlock()
		return token, nil
	}
	if stored.RefreshToken == "" {
		p.mu.Unlock()
		p.decision.unlock()
		return "", ErrNotAuthenticated
	}

	// Shared refresh work inherits values from the initiating caller, while
	// cancellation is reference-counted across all waiters below. This avoids
	// one canceled waiter aborting work still needed by another caller.
	refreshCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &refreshCall{
		done:    make(chan struct{}),
		cancel:  cancel,
		waiters: 1,
	}
	p.inflight = call
	p.mu.Unlock()
	p.decision.unlock()

	go p.runRefresh(refreshCtx, call, stored)
	return p.waitForRefresh(ctx, call)
}

func tokenNeedsRefresh(tokens *AuthTokens, now time.Time) bool {
	return tokens.ExpiresAt > 0 && !now.Before(time.UnixMilli(tokens.ExpiresAt).Add(-tokenExpirySkew))
}

func (p *tokenProvider) runRefresh(ctx context.Context, call *refreshCall, source *AuthTokens) {
	var tokens *AuthTokens
	err := p.storage.Update(ctx, func(state *AuthStorageState) error {
		current := state.Auth
		switch {
		case current == nil || current.AccessToken == "":
			return ErrNotAuthenticated
		case current.AccessToken != source.AccessToken || current.RefreshToken != source.RefreshToken:
			// Another Client or process already committed a newer generation.
			tokens = cloneAuth(current)
			return nil
		}
		refreshed, refreshErr := p.auth.RefreshToken(ctx, source.RefreshToken)
		if refreshErr != nil {
			return refreshErr
		}
		if refreshed == nil || refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
			return errors.New("stripelink: token refresh returned unusable credentials")
		}
		tokens = refreshed
		state.Auth = refreshed
		return nil
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	defer call.cancel()

	// Cancellation that detached the call wins over a transport that ignored
	// its context. Holding p.mu through persistence makes the transition
	// ordered with the final waiter's cancellation: credentials can never be
	// written after that waiter has returned.
	active := p.inflight == call && call.waiters > 0 && ctx.Err() == nil
	if err == nil && !active {
		err = contextFailure(ctx)
		if err == nil {
			err = context.Canceled
		}
	}

	call.tokens = tokens
	call.err = err
	close(call.done)
	if p.inflight == call {
		p.inflight = nil
	}
}

func (p *tokenProvider) waitForRefresh(ctx context.Context, call *refreshCall) (string, error) {
	// Prefer a completed shared result over a simultaneous cancellation.
	select {
	case <-call.done:
		return refreshResult(call)
	default:
	}

	select {
	case <-call.done:
		return refreshResult(call)
	case <-ctx.Done():
		p.mu.Lock()
		select {
		case <-call.done:
			p.mu.Unlock()
			return refreshResult(call)
		default:
		}
		call.waiters--
		if call.waiters == 0 && p.inflight == call {
			p.inflight = nil
			call.cancel()
		}
		p.mu.Unlock()
		return "", contextFailure(ctx)
	}
}

func refreshResult(call *refreshCall) (string, error) {
	if call.err != nil {
		return "", call.err
	}
	if call.tokens == nil || call.tokens.AccessToken == "" {
		return "", ErrNotAuthenticated
	}
	return call.tokens.AccessToken, nil
}
