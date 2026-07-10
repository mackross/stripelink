package stripelink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	tokenExpirySkew              = 60 * time.Second
	detachedAuthOperationTimeout = 30 * time.Second
)

// tokenProvider is the storage-backed, auto-refreshing access-token source
// that NewClient wires as the default AccessTokenFunc when neither
// Options.AccessToken nor Options.GetAccessToken is set (GUIDANCE §5.6,
// §6.2 deviation #8 — in JS this logic lives in the CLI). It returns the
// stored access token while valid and, on forceRefresh or expiry (using
// expires_at minus a small skew), calls AuthResource.RefreshToken and
// persists the result.
//
// Refresh is single-flight within one tokenProvider: concurrent callers wait
// for and reuse one RefreshToken result (GUIDANCE §7). Independent Clients do
// not coordinate network calls; applications needing that guarantee should own
// one Client in their process or service.
type tokenProvider struct {
	storage AuthStorage
	auth    *AuthResource

	// decision serializes the gap between reading storage and publishing a new
	// refreshCall.
	decision storageGate
	mu       sync.Mutex
	// inflight is non-nil while a refresh is running; waiters block on done
	// and then read tokens/err. It is the hand-rolled single-flight result
	// share (GUIDANCE §7) — no x/sync dependency.
	inflight *refreshCall
}

// refreshCall carries the shared result of one in-flight token refresh.
type refreshCall struct {
	done chan struct{} // closed when the refresh completes

	// waiters is protected by tokenProvider.mu and is diagnostic only. Once a
	// refresh starts it completes independently of waiter cancellation so a
	// successful remote token rotation is still persisted.
	waiters int
	tokens  *AuthTokens
	err     error
}

// token implements AccessTokenFunc on top of storage and the auth resource.
// It returns ErrNotAuthenticated when storage holds no tokens. For a forced
// refresh it compares request.RejectedToken with the currently stored access
// token; a mismatch means another caller already refreshed this generation,
// so it returns the stored token without refreshing again. Each waiter may
// stop waiting when its own context is canceled. Once started, shared work
// continues under a bounded internal context so remote success can be persisted.
func (p *tokenProvider) token(ctx context.Context, request AccessTokenRequest) (string, error) {
	if err := requireContext(ctx); err != nil {
		return "", err
	}
	if p.storage == nil || p.auth == nil {
		return "", ErrNotAuthenticated
	}

	// Join local shared work before touching storage.
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
	state, err := p.storage.Load(ctx)
	if err != nil {
		p.decision.unlock()
		return "", fmt.Errorf("stripelink: load authentication: %w", err)
	}
	if state == nil {
		p.decision.unlock()
		return "", errors.New("stripelink: load authentication: storage returned nil state")
	}
	stored = cloneAuth(state.Auth)

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

	// Shared refresh work inherits values from the initiating caller but has its
	// own bounded lifetime. Individual callers may stop waiting without making a
	// successful remote rotation impossible to persist.
	refreshCtx, cancel := detachedAuthContext(ctx)
	call := &refreshCall{
		done:    make(chan struct{}),
		waiters: 1,
	}
	p.inflight = call
	p.mu.Unlock()
	p.decision.unlock()

	go func() {
		defer cancel()
		p.runRefresh(refreshCtx, call, stored)
	}()
	return p.waitForRefresh(ctx, call)
}

func tokenNeedsRefresh(tokens *AuthTokens, now time.Time) bool {
	return tokens.ExpiresAt > 0 && !now.Before(time.UnixMilli(tokens.ExpiresAt).Add(-tokenExpirySkew))
}

func detachedAuthContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), detachedAuthOperationTimeout)
}

func (p *tokenProvider) runRefresh(ctx context.Context, call *refreshCall, source *AuthTokens) {
	refreshed, err := p.auth.RefreshToken(ctx, source.RefreshToken)
	if err != nil {
		// Another Client or process may have completed the same generation while
		// this request was in flight. Prefer that committed generation over a
		// redundant refresh failure.
		if state, loadErr := p.storage.Load(ctx); loadErr == nil && state != nil &&
			state.Auth != nil && state.Auth.AccessToken != "" && !sameAuthTokens(state.Auth, source) {
			p.finishRefresh(call, cloneAuth(state.Auth), nil)
			return
		}
		p.finishRefresh(call, nil, err)
		return
	}
	if refreshed == nil || refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		p.finishRefresh(call, nil, errors.New("stripelink: token refresh returned unusable credentials"))
		return
	}

	commitCtx, cancel := detachedAuthContext(ctx)
	defer cancel()
	tokens := refreshed
	err = p.storage.Transact(commitCtx, func(state *AuthStorageState) error {
		current := state.Auth
		switch {
		case current == nil || current.AccessToken == "":
			return ErrNotAuthenticated
		case !sameAuthTokens(current, source):
			// Another Client or process already committed a newer generation.
			tokens = cloneAuth(current)
			return nil
		}
		state.Auth = refreshed
		return nil
	})
	if err != nil {
		err = fmt.Errorf("stripelink: persist refreshed authentication: %w", err)
		tokens = nil
	}
	p.finishRefresh(call, tokens, err)
}

func (p *tokenProvider) finishRefresh(call *refreshCall, tokens *AuthTokens, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

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
		if call.waiters > 0 {
			call.waiters--
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
