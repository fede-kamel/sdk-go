// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoWSHandler accepts a WebSocket connection and echoes every binary
// message back to the sender until the client disconnects.
func echoWSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = conn.CloseNow() }()

	ctx := r.Context()
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if err := conn.Write(ctx, typ, data); err != nil {
			return
		}
	}
}

// startEchoServer starts an HTTP test server that upgrades connections to
// WebSocket and echoes binary messages. Returns the server and its ws:// URL.
func startEchoServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(echoWSHandler))
	t.Cleanup(srv.Close)
	// Convert http://host:port to ws://host:port.
	wsURL := "ws" + srv.URL[len("http"):]
	return srv, wsURL
}

// startTLSEchoServer starts a TLS HTTP test server. Returns the server,
// its wss:// URL, and a tls.Config that trusts the server's certificate.
func startTLSEchoServer(t *testing.T) (*httptest.Server, string, *tls.Config) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(echoWSHandler))
	t.Cleanup(srv.Close)
	wssURL := "wss" + srv.URL[len("https"):]

	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())
	tlsCfg := &tls.Config{
		RootCAs: certPool,
	}
	return srv, wssURL, tlsCfg
}

// testLogger captures log messages for assertions.
type testLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *testLogger) Debug(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, "DEBUG: "+msg)
}

func (l *testLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, "INFO: "+msg)
}

func (l *testLogger) Error(_ error, msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, "ERROR: "+msg)
}

func (l *testLogger) Messages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]string, len(l.messages))
	copy(cp, l.messages)
	return cp
}

// --- Test: NewTunnelProxy creation ---

func TestNewTunnelProxy_ValidURL(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "edge-token-123")
	require.NoError(t, err)
	require.NotNil(t, tp)
	defer func() { _ = tp.Close() }()

	// Addr() must return a non-empty, dialable address.
	addr := tp.Addr()
	assert.NotEmpty(t, addr)

	// Verify the address is dialable.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	_ = conn.Close()
}

func TestNewTunnelProxy_EmptyURL(t *testing.T) {
	_, err := NewTunnelProxy("", "edge-token-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway URL")
}

func TestNewTunnelProxy_InvalidURL(t *testing.T) {
	_, err := NewTunnelProxy("://bad-url", "edge-token-123")
	require.Error(t, err)
}

func TestNewTunnelProxy_WrongScheme(t *testing.T) {
	_, err := NewTunnelProxy("http://gateway.example.com", "edge-token-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ws:// or wss://")
}

func TestNewTunnelProxy_RejectsCredentialBearingRemoteWS(t *testing.T) {
	_, err := NewTunnelProxy("ws://gateway.example.com/tunnel", "edge-token-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wss://")
}

func TestNewTunnelProxy_EmptyHost(t *testing.T) {
	_, err := NewTunnelProxy("ws://", "edge-token-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must include a host")
}

func TestNewTunnelProxy_EmptyEdgeToken(t *testing.T) {
	_, wsURL := startEchoServer(t)

	_, err := NewTunnelProxy(wsURL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edge token")
}

func TestNewTunnelProxy_TokenNotInError(t *testing.T) {
	// Verify error messages do not leak the edge token.
	_, err := NewTunnelProxy("", "super-secret-token-abc")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-token-abc")
}

// --- Test: Addr ---

func TestTunnelProxy_Addr_Dialable(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	addr := tp.Addr()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.NotEmpty(t, host)
	assert.NotEmpty(t, port)
}

// --- Test: Close on unused proxy ---

func TestTunnelProxy_Close_Unused(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)

	// Close immediately without any connections should return nil.
	err = tp.Close()
	assert.NoError(t, err)
}

// --- Test: Close drains in-flight connections ---

func TestTunnelProxy_Close_DrainsInFlight(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok", WithCloseTimeout(5*time.Second))
	require.NoError(t, err)

	// Establish a connection through the tunnel.
	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)

	// Send data through the tunnel and verify echo.
	testData := []byte("hello tunnel")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Give the tunnel time to relay.
	time.Sleep(100 * time.Millisecond)

	// Close the client connection first so the bridge goroutine can drain.
	_ = conn.Close()

	// Now close the tunnel; should drain cleanly.
	err = tp.Close()
	assert.NoError(t, err)
}

// --- Test: Close force-closes after timeout ---

func TestTunnelProxy_Close_ForceClosesAfterTimeout(t *testing.T) {
	// Use a slow handler that holds connections open.
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer func() { _ = wsConn.CloseNow() }()
		// Hold the connection open for a long time.
		ctx := r.Context()
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	})
	srv := httptest.NewServer(slowHandler)
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	// Use a very short close timeout and a logger to verify timeout logging.
	logger := &testLogger{}
	tp, err := NewTunnelProxy(wsURL, "tok", WithCloseTimeout(200*time.Millisecond), WithTunnelLogger(logger))
	require.NoError(t, err)

	// Establish a connection that will be held open by the slow handler.
	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Write something to trigger the WebSocket dial.
	_, _ = conn.Write([]byte("trigger"))

	// Give the tunnel time to establish the bridge.
	time.Sleep(100 * time.Millisecond)

	// Close should force-close after the short timeout, not hang.
	start := time.Now()
	err = tp.Close()
	elapsed := time.Since(start)

	// Should complete within a reasonable time (timeout + margin).
	assert.Less(t, elapsed, 2*time.Second, "Close should not hang beyond timeout")
	// err may or may not be nil depending on force-close; we don't assert on it.
	_ = err

	// Verify the timeout was logged.
	msgs := logger.Messages()
	assert.True(t, slices.Contains(msgs, "INFO: tunnel close timeout reached, force-closing"),
		"expected timeout log message, got: %v", msgs)
}

// --- Test: Concurrent Close is safe ---

func TestTunnelProxy_Close_ConcurrentSafe(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)

	// Call Close concurrently from multiple goroutines.
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = tp.Close()
		}(i)
	}
	wg.Wait()

	// All calls should succeed without panic.
	for _, e := range errs {
		assert.NoError(t, e)
	}
}

// --- Test: Goroutine cleanup ---

func TestTunnelProxy_GoroutineCleanup(t *testing.T) {
	_, wsURL := startEchoServer(t)

	// Record baseline goroutine count.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)

	// Open several connections.
	conns := make([]net.Conn, 5)
	for i := range conns {
		c, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
		require.NoError(t, err)
		_, _ = fmt.Fprintf(c, "msg-%d", i)
		conns[i] = c
	}

	// Let bridges establish.
	time.Sleep(100 * time.Millisecond)

	// Close all client connections.
	for _, c := range conns {
		_ = c.Close()
	}

	// Close the tunnel.
	err = tp.Close()
	require.NoError(t, err)

	// Wait for goroutines to wind down.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	// Goroutine count should return to near baseline.
	// Allow a small margin for runtime goroutines.
	final := runtime.NumGoroutine()
	assert.LessOrEqual(t, final, baseline+3,
		"goroutine leak: baseline=%d, final=%d", baseline, final)
}

// --- Test: Concurrent streams ---

func TestTunnelProxy_ConcurrentStreams(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	const streamCount = 10
	var wg sync.WaitGroup
	errs := make(chan error, streamCount)

	for i := range streamCount {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
			if err != nil {
				errs <- fmt.Errorf("stream %d dial: %w", idx, err)
				return
			}
			defer func() { _ = conn.Close() }()

			msg := fmt.Sprintf("stream-%d-data", idx)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				errs <- fmt.Errorf("stream %d write: %w", idx, err)
				return
			}

			// Read echo response.
			buf := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := io.ReadFull(conn, buf)
			if err != nil {
				errs <- fmt.Errorf("stream %d read: %w (got %d bytes)", idx, err, n)
				return
			}

			if string(buf) != msg {
				errs <- fmt.Errorf("stream %d: expected %q, got %q", idx, msg, string(buf))
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --- Test: TLS option ---

func TestTunnelProxy_TLSOption(t *testing.T) {
	_, wssURL, tlsCfg := startTLSEchoServer(t)

	tp, err := NewTunnelProxy(wssURL, "tok", WithTunnelTLS(tlsCfg))
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	// Verify we can communicate through the TLS tunnel.
	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	msg := []byte("tls-echo-test")
	_, err = conn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf)
}

// --- Test: Logger option ---

func TestTunnelProxy_LoggerOption(t *testing.T) {
	_, wsURL := startEchoServer(t)

	logger := &testLogger{}
	tp, err := NewTunnelProxy(wsURL, "tok", WithTunnelLogger(logger))
	require.NoError(t, err)

	// Open a connection to trigger log events.
	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)

	_, _ = conn.Write([]byte("log-test"))

	// Give the tunnel time to process.
	time.Sleep(200 * time.Millisecond)

	_ = conn.Close()

	err = tp.Close()
	require.NoError(t, err)

	// Logger should have received at least one message.
	msgs := logger.Messages()
	assert.NotEmpty(t, msgs, "logger should receive log events")
}

// --- Test: WithCloseTimeout option ---

func TestWithCloseTimeout(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok", WithCloseTimeout(10*time.Second))
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	// We can't directly inspect the config, but creation should succeed.
	assert.NotNil(t, tp)
}

// --- Test: Data flows through the tunnel ---

func TestTunnelProxy_DataRoundTrip(t *testing.T) {
	_, wsURL := startEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "tok")
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send data and verify round-trip through the WebSocket echo server.
	msg := []byte("round-trip-payload-12345")
	_, err = conn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)

	assert.Equal(t, msg, buf)
}

// handshakeRecorder echoes like echoWSHandler and records the headers of
// every WebSocket handshake it accepts.
type handshakeRecorder struct {
	mu      sync.Mutex
	headers []http.Header
}

func (rec *handshakeRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.headers = append(rec.headers, r.Header.Clone())
	rec.mu.Unlock()
	echoWSHandler(w, r)
}

// Headers returns a copy of the recorded handshake headers in order.
func (rec *handshakeRecorder) Headers() []http.Header {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return slices.Clone(rec.headers)
}

// startRecordingEchoServer starts an echo server that records handshake
// headers. Returns the recorder and the server's ws:// URL.
func startRecordingEchoServer(t *testing.T) (*handshakeRecorder, string) {
	t.Helper()
	rec := &handshakeRecorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return rec, "ws" + srv.URL[len("http"):]
}

// roundTrip opens one connection through the tunnel, sends msg and returns
// the echoed bytes. The error is the first write or read failure.
func roundTrip(t *testing.T, tp *TunnelProxy, msg string) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", tp.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(msg)); err != nil {
		return "", err
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(conn, buf)
	return string(buf[:n]), err
}

// --- Test: edge token headers on the WebSocket handshake ---

func TestNewTunnelProxy_SendsEdgeTokenOnDial(t *testing.T) {
	rec, wsURL := startRecordingEchoServer(t)

	tp, err := NewTunnelProxy(wsURL, "fixed-token")
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	got, err := roundTrip(t, tp, "ping")
	require.NoError(t, err)
	assert.Equal(t, "ping", got)

	headers := rec.Headers()
	require.Len(t, headers, 1)
	assert.Equal(t, "fixed-token", headers[0].Get("cf-access-jwt-assertion"))
	assert.Equal(t, "CF_Authorization=fixed-token", headers[0].Get("cookie"))
}

// --- Test: token source ---

func TestNewTunnelProxyWithTokenSource_NilSource(t *testing.T) {
	_, wsURL := startEchoServer(t)

	_, err := NewTunnelProxyWithTokenSource(wsURL, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token source")
}

func TestNewTunnelProxyWithTokenSource_RereadsTokenPerDial(t *testing.T) {
	rec, wsURL := startRecordingEchoServer(t)

	oldToken, newToken := "old-token", "new-token"
	var current atomic.Pointer[string]
	current.Store(&oldToken)
	var calls atomic.Int32

	tp, err := NewTunnelProxyWithTokenSource(wsURL, func() (string, error) {
		calls.Add(1)
		return *current.Load(), nil
	})
	require.NoError(t, err)
	defer func() { _ = tp.Close() }()

	got, err := roundTrip(t, tp, "first")
	require.NoError(t, err)
	assert.Equal(t, "first", got)

	// The CLI rewrites the token while the proxy keeps running.
	current.Store(&newToken)

	got, err = roundTrip(t, tp, "second")
	require.NoError(t, err)
	assert.Equal(t, "second", got)

	headers := rec.Headers()
	require.Len(t, headers, 2)
	assert.Equal(t, "old-token", headers[0].Get("cf-access-jwt-assertion"))
	assert.Equal(t, "CF_Authorization=old-token", headers[0].Get("cookie"))
	assert.Equal(t, "new-token", headers[1].Get("cf-access-jwt-assertion"),
		"second dial must not reuse the stale token")
	assert.Equal(t, "CF_Authorization=new-token", headers[1].Get("cookie"))
	assert.EqualValues(t, 2, calls.Load(), "token source should be called once per dial")
}

func TestNewTunnelProxyWithTokenSource_RetriesSourceAfterFailure(t *testing.T) {
	tests := []struct {
		name string
		fail func() (string, error)
	}{
		{"error", func() (string, error) { return "", errors.New("edge_token missing") }},
		{"empty", func() (string, error) { return "", nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, wsURL := startRecordingEchoServer(t)

			var mu sync.Mutex
			var current string
			src := func() (string, error) {
				mu.Lock()
				defer mu.Unlock()
				if current == "" {
					return tc.fail()
				}
				return current, nil
			}

			logger := &testLogger{}
			tp, err := NewTunnelProxyWithTokenSource(wsURL, src, WithTunnelLogger(logger))
			require.NoError(t, err)
			defer func() { _ = tp.Close() }()

			// Without a token the tunnel must close the local connection
			// without dialing the gateway.
			_, err = roundTrip(t, tp, "blocked")
			require.Error(t, err)
			assert.Empty(t, rec.Headers(), "no WebSocket handshake without a token")
			assert.Contains(t, logger.Messages(), "ERROR: tunnel edge token load failed")

			// The token appears later, as after `openshell gateway login`.
			mu.Lock()
			current = "late-token"
			mu.Unlock()

			got, err := roundTrip(t, tp, "allowed")
			require.NoError(t, err)
			assert.Equal(t, "allowed", got)

			headers := rec.Headers()
			require.Len(t, headers, 1)
			assert.Equal(t, "late-token", headers[0].Get("cf-access-jwt-assertion"))
		})
	}
}
