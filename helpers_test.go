package stripelink

// Shared test fakes for the conformance suite (GUIDANCE §8):
//
//   - recordingTransport: an http.RoundTripper that records every request
//     (method, URL, headers, body) and returns scripted responses in order —
//     the Go analogue of the JS tests' stubbed fetch.
//   - newCapturingLogger / capturedLog: a slog handler that records rendered
//     log lines so tests can assert redaction placeholders appear and raw
//     secrets never do.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// nilContext returns a deliberately invalid context for public API robustness
// tests. Keeping the nil behind a named helper makes the exceptional test
// intent explicit while leaving staticcheck's SA1012 enabled globally.
func nilContext() context.Context { return nil }

// recordedRequest captures one HTTP request seen by a recordingTransport.
type recordedRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   string
}

// scriptedResponse describes one response a recordingTransport will return.
type scriptedResponse struct {
	status int
	header http.Header
	body   string
}

// recordingTransport is an http.RoundTripper test fake. Script responses
// with respond (consumed in FIFO order), then assert on Requests. When err
// is set, every RoundTrip fails with it after recording the request,
// simulating a network-level failure. Safe for concurrent use.
type recordingTransport struct {
	mu        sync.Mutex
	requests  []recordedRequest
	responses []scriptedResponse
	err       error
}

// respond queues a response with the given status and body.
func (rt *recordingTransport) respond(status int, body string) {
	rt.respondWithHeader(status, nil, body)
}

// respondWithHeader queues a response with the given status, header, and body.
func (rt *recordingTransport) respondWithHeader(status int, header http.Header, body string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.responses = append(rt.responses, scriptedResponse{status: status, header: header, body: body})
}

// failWith makes every subsequent RoundTrip return err after recording the
// request.
func (rt *recordingTransport) failWith(err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.err = err
}

// RoundTrip implements http.RoundTripper: it records the request and returns
// the next scripted response.
func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("recordingTransport: read request body: %w", err)
		}
		body = string(b)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.requests = append(rt.requests, recordedRequest{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: req.Header.Clone(),
		Body:   body,
	})

	if rt.err != nil {
		return nil, rt.err
	}
	if len(rt.responses) == 0 {
		return nil, fmt.Errorf("recordingTransport: no scripted response for %s %s", req.Method, req.URL)
	}
	resp := rt.responses[0]
	rt.responses = rt.responses[1:]

	header := resp.header
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", resp.status, http.StatusText(resp.status)),
		StatusCode:    resp.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(resp.body)),
		ContentLength: int64(len(resp.body)),
		Request:       req,
	}, nil
}

// Requests returns a copy of every request recorded so far.
func (rt *recordingTransport) Requests() []recordedRequest {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]recordedRequest, len(rt.requests))
	copy(out, rt.requests)
	return out
}

// client returns an *http.Client routed through this transport, for use as
// Options.HTTPClient.
func (rt *recordingTransport) client() *http.Client {
	return &http.Client{Transport: rt}
}

// capturedLog accumulates rendered log lines from a capturingHandler. Safe
// for concurrent use.
type capturedLog struct {
	mu    sync.Mutex
	lines []string
}

// Lines returns a copy of every captured log line.
func (c *capturedLog) Lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

// Contains reports whether any captured line contains substr — used to assert
// that redaction placeholders appear and raw secrets do not.
func (c *capturedLog) Contains(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range c.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// newCapturingLogger returns a debug-level *slog.Logger whose output is
// captured in the returned capturedLog, for redaction assertions.
func newCapturingLogger() (*slog.Logger, *capturedLog) {
	state := &capturedLog{}
	return slog.New(&capturingHandler{state: state}), state
}

// capturingHandler is a slog.Handler that renders each record — message plus
// attributes — into a single line on its shared capturedLog.
type capturingHandler struct {
	state *capturedLog
	attrs []slog.Attr
}

// Enabled reports that every level is enabled; the SDK's Verbose flag, not
// the handler, gates logging.
func (h *capturingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

// Handle renders r and appends it to the shared capturedLog.
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	appendAttr := func(a slog.Attr) bool {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
		return true
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(appendAttr)

	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	h.state.lines = append(h.state.lines, sb.String())
	return nil
}

// WithAttrs returns a handler that prefixes attrs onto every rendered line,
// sharing the same capturedLog.
func (h *capturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := &capturingHandler{state: h.state}
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return clone
}

// WithGroup returns the handler unchanged; group qualification is not needed
// for redaction assertions.
func (h *capturingHandler) WithGroup(string) slog.Handler {
	return h
}
