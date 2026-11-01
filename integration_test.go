package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestProxyEndToEnd exercises the full explicit-proxy MITM pipeline: a client
// connects through the proxy, the target bundle is intercepted, patched, and
// returned. The upstream is a local TLS server, and the client trusts the MITM
// CA, exactly like a real browser would after installing the CA.
func TestProxyEndToEnd(t *testing.T) {
	const bundle = `if(!Qa())return this.router.navigateByUrl("/unsupported-country");if(!Rb())return n("/age-restricted");`

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, bundle)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	s := newServer(defaultConfig(), log.New(io.Discard, "", 0))
	// Point the proxy's upstream transport at the local server and accept its
	// self-signed certificate (a real deployment verifies upstream normally).
	s.transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	s.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamURL.Host)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := &http.Server{Handler: s.newProxyHandler()}
	go func() { _ = proxyServer.Serve(ln) }()
	defer proxyServer.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())

	pool := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(s.ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get("https://www.gstatic.com/x/AiSandboxAngularFrontend/m=_b")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "if(false)return this.router.navigateByUrl") {
		t.Fatalf("expected patched bundle through the proxy, got:\n%s", body)
	}

	s.mu.Lock()
	strategy := s.run.LastPatchStrategy
	s.mu.Unlock()
	if strategy != "route-guard-v1" {
		t.Fatalf("expected route-guard-v1 recorded, got %q", strategy)
	}
}

// TestProxyRedirect verifies that a request to /unsupported-country is answered
// with a redirect to the Flow home page.
func TestProxyRedirect(t *testing.T) {
	s := newServer(defaultConfig(), log.New(io.Discard, "", 0))

	// No real upstream needed for the redirect path, but dialing is never hit.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := &http.Server{Handler: s.newProxyHandler()}
	go func() { _ = proxyServer.Serve(ln) }()
	defer proxyServer.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	pool := x509.NewCertPool()
	caCert, _ := x509.ParseCertificate(s.ca.Certificate[0])
	pool.AddCert(caCert)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get("https://flow.google.com/unsupported-country")
	if err != nil {
		t.Fatalf("GET redirect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != FLOW_HOME {
		t.Fatalf("Location = %q, want %q", loc, FLOW_HOME)
	}
}
