/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
)

// Regression tests for the golang.org/x/net/http2 -> net/http (Go 1.24)
// migration (issue #446). The migration changed which HTTP/2 implementation
// serves live traffic; these tests pin the observable end-to-end behaviour
// that must not change:
//
//   - the secure listener must negotiate "h2" via ALPN. Run serves through a
//     pre-made tls.NewListener + srv.Serve, where the stdlib does NOT add "h2"
//     to NextProtos automatically (unlike ListenAndServeTLS). Run appends it
//     explicitly; losing that line silently downgrades all HTTPS clients to
//     HTTP/1.1.
//   - the insecure listener must answer prior-knowledge h2c requests, the
//     replacement for the removed h2c.NewHandler wrapping.
//   - the secure listener must serve HTTP/1.1 clients too (ALPN "http/1.1").
//   - Complete must translate the http2.* flags into http.HTTP2Config fields.
//
// Run requires a kubeconfig; the tests hand it a syntactically valid one. The
// proxy's upstream URL points at a reserved port nothing listens on: requests
// are unauthenticated, so authn rejects them with 403 before any upstream
// dial happens. No Kubernetes cluster is needed either — clientcmd only parses
// the kubeconfig file lazily on first API call, which never occurs.

func testKubeconfig(t *testing.T) string {
	t.Helper()
	kc := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test
contexts:
- context:
    cluster: test
  name: test
current-context: test
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kc), 0o600); err != nil {
		t.Fatalf("failed to write kubeconfig: %v", err)
	}
	return path
}

// freeAddr returns a 127.0.0.1:<port> address that was free at call time.
// Run binds it a moment later; the tiny race is standard Go test practice.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

// completedOptions runs Complete for a proxy bound to the given flags.
func completedOptions(t *testing.T, secureAddr, insecureAddr string) *completedProxyRunOptions {
	t.Helper()
	o := options.NewProxyRunOptions()
	o.KubeconfigLocation = testKubeconfig(t)
	// Authn rejects before upstream dialing, so any parseable URL works.
	o.Upstream = "http://127.0.0.1:1"
	o.SecureListenAddress = secureAddr
	o.InsecureListenAddress = insecureAddr
	cfg, err := Complete(o)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return cfg
}

// startProxy boots Run and waits until addr accepts TCP connections.
func startProxy(t *testing.T, cfg *completedProxyRunOptions, addr string) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(cfg) }()
	// Run only exits on failure here; if it ever does, the test hangs in
	// cleanup rather than failing cleanly. No graceful stop exists on Run.
	t.Cleanup(func() {}) // Run has no shutdown hook; process teardown closes sockets

	for deadline := time.Now().Add(10 * time.Second); ; {
		select {
		case err := <-errCh:
			t.Fatalf("Run returned before serving: %v", err)
		default:
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start listening on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSecureListenerNegotiatesH2OverALPN(t *testing.T) {
	addr := freeAddr(t)
	startProxy(t, completedOptions(t, addr, ""), addr)

	probe := func(protos []string, want string) {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed test server
			NextProtos:         protos,
		})
		if err != nil {
			t.Fatalf("failed to TLS-dial secure listener with %v: %v", protos, err)
		}
		defer conn.Close()
		if got := conn.ConnectionState().NegotiatedProtocol; got != want {
			t.Fatalf("offered %v: expected negotiated protocol %q, got %q", protos, want, got)
		}
	}

	probe([]string{"h2"}, "h2")
	probe([]string{"http/1.1"}, "http/1.1")
}

func TestSecureListenerServesHTTP1(t *testing.T) {
	addr := freeAddr(t)
	startProxy(t, completedOptions(t, addr, ""), addr)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test server
	}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTP/1.1 request failed: %v", err)
	}
	defer resp.Body.Close()
	// 401 = unauthenticated; authn rejected before any authz/upstream call,
	// proving the TLS + HTTP/1.1 transport worked end to end.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %s", resp.Status)
	}
	if got := resp.ProtoMajor; got != 1 {
		t.Fatalf("expected HTTP/1.x response, got HTTP/%d", got)
	}
}

func TestInsecureListenerServesH2C(t *testing.T) {
	addr := freeAddr(t)
	startProxy(t, completedOptions(t, "", addr), addr)

	// h2c prior-knowledge client (stdlib, mirrors test/e2e/h2c_upstream.go).
	tr := &http.Transport{}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	tr.Protocols = &p
	client := &http.Client{Transport: tr}

	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	defer resp.Body.Close()

	// 401 = unauthenticated; proves h2c served the request end to end.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 over h2c, got %s", resp.Status)
	}
	if got := resp.ProtoMajor; got != 2 {
		t.Fatalf("expected HTTP/2 response over h2c, got HTTP/%d", got)
	}
}

func TestInsecureListenerServesHTTP1(t *testing.T) {
	addr := freeAddr(t)
	startProxy(t, completedOptions(t, "", addr), addr)

	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("HTTP/1.1 request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %s", resp.Status)
	}
	if got := resp.ProtoMajor; got != 1 {
		t.Fatalf("expected HTTP/1.x response, got HTTP/%d", got)
	}
}

func TestCompleteMapsHTTP2Config(t *testing.T) {
	o := options.NewProxyRunOptions()
	o.KubeconfigLocation = testKubeconfig(t)
	o.Upstream = "http://127.0.0.1:1"
	o.HTTP2MaxSize = 1024
	o.HTTP2MaxConcurrentStreams = 2

	cfg, err := Complete(o)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	h2 := cfg.http2Config()
	if h2 == nil {
		t.Fatal("http2Config() returned nil")
	}
	if h2.MaxConcurrentStreams != 2 {
		t.Errorf("MaxConcurrentStreams = %d, want 2", h2.MaxConcurrentStreams)
	}
	if h2.MaxReadFrameSize != 1024 {
		t.Errorf("MaxReadFrameSize = %d, want 1024", h2.MaxReadFrameSize)
	}
	if h2.MaxReceiveBufferPerStream != 1024 {
		t.Errorf("MaxReceiveBufferPerStream = %d, want 1024", h2.MaxReceiveBufferPerStream)
	}
	if h2.MaxReceiveBufferPerConnection != 2048 {
		t.Errorf("MaxReceiveBufferPerConnection = %d, want 2048", h2.MaxReceiveBufferPerConnection)
	}
}
