package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"golang.org/x/net/http2"
)

const (
	FLOW_HOME             = "https://flow.google.com/"
	FLOW_HOST             = "flow.google.com"
	TARGET_HOST           = "www.gstatic.com"
	TARGET_BUNDLE_MARKER  = "AiSandboxAngularFrontend"
	TARGET_BUNDLE_SUFFIX  = "/m=_b"
	defaultConnectTimeout = 15 * time.Second
)

var unsupportedCountryPathRe = regexp.MustCompile(`/(?:unsupported-country)/?$`)

// RunInfo mirrors the extension's "last run" state and is written to the status
// file after every patch attempt or error.
type RunInfo struct {
	LastError         string `json:"last_error,omitempty"`
	LastPatchedURL    string `json:"last_patched_url,omitempty"`
	LastPatchStrategy string `json:"last_patch_strategy,omitempty"`
	LastRunAt         string `json:"last_run_at,omitempty"`
}

type server struct {
	cfg             *Config
	logger          *log.Logger
	ca              tls.Certificate
	store           *caStore
	transport       *http.Transport
	enabled         atomic.Bool
	handleRedirect  atomic.Bool
	cooldownNs      atomic.Int64
	mu              sync.Mutex
	run             RunInfo
	lastRedirect    map[string]time.Time
}

func newServer(cfg *Config, logger *log.Logger) *server {
	ca, custom := loadCA(cfg.CACert, cfg.CAKey)
	if !custom {
		logger.Printf("WARNING: using goproxy's built-in CA (its private key is public). Run gen-ca.sh and set ca_cert/ca_key for a unique CA.")
	}

	transport := &http.Transport{
		Proxy:              nil, // never chain through an upstream proxy (prevents loops)
		DialContext:        (&net.Dialer{Timeout: defaultConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:  true,
		MaxIdleConns:       64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:    60 * time.Second,
		TLSHandshakeTimeout: defaultConnectTimeout,
	}

	s := &server{
		cfg:          cfg,
		logger:       logger,
		ca:           ca,
		store:        newCAStore(ca),
		transport:    transport,
		lastRedirect: make(map[string]time.Time),
	}
	s.applyRuntime(cfg)
	return s
}

func (s *server) applyRuntime(cfg *Config) {
	s.enabled.Store(cfg.Enabled)
	s.handleRedirect.Store(cfg.HandleRedirect)
	s.cooldownNs.Store(int64(time.Duration(cfg.CooldownSeconds) * time.Second))
}

// --- predicates -------------------------------------------------------------

func isTargetBundle(u *url.URL) bool {
	if u == nil {
		return false
	}
	return u.Scheme == "https" &&
		u.Hostname() == TARGET_HOST &&
		strings.Contains(u.Path, TARGET_BUNDLE_MARKER) &&
		strings.HasSuffix(u.Path, TARGET_BUNDLE_SUFFIX)
}

func isUnsupportedCountryURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	return u.Scheme == "https" &&
		u.Hostname() == FLOW_HOST &&
		unsupportedCountryPathRe.MatchString(u.Path)
}

func hostname(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

func clientIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func (s *server) isMitmHost(host string) bool {
	if host == TARGET_HOST {
		return true
	}
	if host == FLOW_HOST {
		return s.handleRedirect.Load()
	}
	return false
}

// --- state ---------------------------------------------------------------

func (s *server) recordSuccess(url, strategy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.run = RunInfo{
		LastPatchedURL:    url,
		LastPatchStrategy: strategy,
		LastRunAt:         time.Now().UTC().Format(time.RFC3339),
	}
	s.writeStatusLocked()
}

func (s *server) recordError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.run.LastError = err
	s.run.LastRunAt = time.Now().UTC().Format(time.RFC3339)
	s.writeStatusLocked()
}

func (s *server) writeStatusLocked() {
	if s.cfg.StatusFile == "" {
		return
	}
	if dir := filepath.Dir(s.cfg.StatusFile); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	data, err := json.MarshalIndent(s.run, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.cfg.StatusFile, data, 0o644)
}

func (s *server) redirectRecently(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.lastRedirect[ip]
	if !ok {
		return false
	}
	return time.Since(last) < time.Duration(s.cooldownNs.Load())
}

func (s *server) markRedirect(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRedirect[ip] = time.Now()
}

// --- response pipeline ------------------------------------------------------

// roundTrip forwards a request upstream. It strips Accept-Encoding so the
// transport transparently negotiates and decodes gzip, leaving decompressed
// bodies for the patch pipeline.
func (s *server) roundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("Accept-Encoding")
	req.Header.Del("Proxy-Connection")
	return s.transport.RoundTrip(req)
}

// processRequest returns a synthetic response when the request should be
// short-circuited (i.e. the unsupported-country redirect handling), or nil to
// proceed upstream.
func (s *server) processRequest(req *http.Request) *http.Response {
	if !s.enabled.Load() || !s.handleRedirect.Load() {
		return nil
	}
	if req.URL == nil || !isUnsupportedCountryURL(req.URL) {
		return nil
	}

	ip := clientIP(req)
	if s.redirectRecently(ip) {
		s.recordError("Repeated unsupported-country redirect was stopped.")
		return s.errorPage(req, http.StatusForbidden, "Repeated unsupported-country redirect was stopped.")
	}

	s.markRedirect(ip)
	return s.redirect(req, FLOW_HOME)
}

// patchResponse applies the bundle patch when the response is the target Flow
// bundle. On a patch mismatch it passes the original body through unchanged and
// records the error, exactly like the extension's continueOriginal path.
func (s *server) patchResponse(req *http.Request, resp *http.Response) *http.Response {
	if resp == nil || !s.enabled.Load() {
		return resp
	}
	if req == nil || req.URL == nil || !isTargetBundle(req.URL) {
		return resp
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.recordError(fmt.Sprintf("Unexpected bundle response status: %d.", resp.StatusCode))
		return resp
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		s.recordError("Failed to read bundle response: " + err.Error())
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	}

	result := PatchSource(string(body))
	if result.OK {
		s.recordSuccess(req.URL.String(), result.Strategy)
		resp.Body = io.NopCloser(bytes.NewReader([]byte(result.Source)))
		fixPatchedHeaders(resp, len(result.Source))
	} else {
		s.recordError(result.Error)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp
}

func fixPatchedHeaders(resp *http.Response, bodyLen int) {
	for _, h := range []string{
		"Age", "Cache-Control", "Content-Encoding", "Content-Length",
		"Content-MD5", "ETag", "Last-Modified", "Transfer-Encoding",
	} {
		resp.Header.Del(h)
	}
	resp.Header.Set("Cache-Control", "no-store")
	resp.ContentLength = int64(bodyLen)
	resp.TransferEncoding = nil
}

// --- synthetic responses ----------------------------------------------------

func newResponse(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func (s *server) redirect(req *http.Request, location string) *http.Response {
	resp := newResponse(req, http.StatusFound, "text/html; charset=utf-8",
		`<!doctype html><html><body>Redirecting to Flow…</body></html>`)
	resp.Header.Set("Location", location)
	return resp
}

func (s *server) errorPage(req *http.Request, status int, message string) *http.Response {
	return newResponse(req, status, "text/plain; charset=utf-8", message+"\n")
}

// --- explicit proxy (goproxy) ----------------------------------------------

func (s *server) newProxyHandler() *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = s.transport
	proxy.CertStore = s.store
	proxy.Verbose = s.cfg.Verbose
	proxy.Logger = s.logger
	proxy.AllowHTTP2 = true
	proxy.NonproxyHandler = http.HandlerFunc(s.transparentHTTP)

	mitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&s.ca),
	}

	// MITM only our two target hosts; every other CONNECT is tunneled.
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		h := hostname(host)
		if s.isMitmHost(h) {
			return mitm, host
		}
		return nil, ""
	})

	// Short-circuit the /unsupported-country navigation with a redirect.
	proxy.OnRequest(goproxy.DstHostIs(FLOW_HOST)).DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if resp := s.processRequest(req); resp != nil {
			return nil, resp
		}
		return req, nil
	})

	// Patch the target bundle on the way back.
	proxy.OnResponse(goproxy.DstHostIs(TARGET_HOST)).DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return s.patchResponse(ctx.Req, resp)
	})

	return proxy
}

// --- transparent HTTP (iptables REDIRECT of port 80) ------------------------

// transparentHTTP handles origin-form requests that arrive without a proxy
// CONNECT. goproxy routes these to NonproxyHandler.
func (s *server) transparentHTTP(w http.ResponseWriter, r *http.Request) {
	u := *r.URL
	u.Scheme = "http"
	u.Host = r.Host
	req := r.Clone(r.Context())
	req.URL = &u
	req.RequestURI = ""

	var resp *http.Response
	if pr := s.processRequest(req); pr != nil {
		resp = pr
	} else {
		var err error
		resp, err = s.roundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp = s.patchResponse(req, resp)
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// --- transparent HTTPS (iptables REDIRECT of port 443) ----------------------

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (s *server) serveTransparentHTTPS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Printf("transparent HTTPS accept error: %v", err)
			return
		}
		go s.handleTransparentHTTPSConn(conn)
	}
}

func (s *server) handleTransparentHTTPSConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(defaultConnectTimeout))
	br := bufio.NewReader(conn)
	sni, err := clientHelloSNI(br)
	if err != nil || sni == "" {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if !s.isMitmHost(sni) {
		s.tunnel(br, conn, net.JoinHostPort(sni, "443"))
		return
	}

	tlsCfg, err := s.store.tlsConfig(sni)
	if err != nil {
		s.logger.Printf("leaf certificate for %s failed: %v", sni, err)
		return
	}

	tlsConn := tls.Server(&bufferedConn{Conn: conn, r: br}, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		s.serveMitmHTTP2(tlsConn, sni)
		return
	}
	s.serveMitmConn(tlsConn, sni)
}

// tunnel relays raw bytes to the upstream host for non-target connections.
// br already contains the bytes read while peeking the SNI, and io.Copy drains
// them first.
func (s *server) tunnel(br *bufio.Reader, conn net.Conn, addr string) {
	upstream, err := net.DialTimeout("tcp", addr, defaultConnectTimeout)
	if err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = upstream.Close()
	_ = conn.Close()
}

// handleReq runs the full MITM pipeline for one request and returns the
// response to send to the client (either a synthetic redirect/error or the
// forwarded-and-possibly-patched upstream response).
func (s *server) handleReq(req *http.Request, scheme string) *http.Response {
	req.URL.Scheme = scheme
	req.URL.Host = req.Host
	req.RequestURI = ""

	if pr := s.processRequest(req); pr != nil {
		// Synthetic response: drain any request body before replying so the
		// connection stays clean for the next keep-alive request.
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		return pr
	}

	resp, err := s.roundTrip(req)
	if err != nil {
		return newResponse(req, http.StatusBadGateway, "text/plain; charset=utf-8", err.Error())
	}
	return s.patchResponse(req, resp)
}

// serveMitmConn proxies an HTTP/1.1 MITM'd TLS connection, supporting
// keep-alive by looping until the client or upstream closes.
func (s *server) serveMitmConn(client *tls.Conn, host string) {
	defer client.Close()

	br := bufio.NewReader(client)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.RemoteAddr = client.RemoteAddr().String()

		resp := s.handleReq(req, "https")
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		writeErr := resp.Write(client)
		_ = resp.Body.Close()

		if writeErr != nil || req.Close {
			return
		}
	}
}

// serveMitmHTTP2 proxies an HTTP/2 MITM'd TLS connection. HTTP/2 multiplexes
// many requests over one connection, which keeps Flow fast under interception.
func (s *server) serveMitmHTTP2(client *tls.Conn, host string) {
	defer client.Close()
	h2 := &http2.Server{}
	h2.ServeConn(client, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := s.handleReq(r, "https")
			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		}),
	})
}

func (s *server) writeError(w io.Writer, code int, err error) {
	resp := newResponse(nil, code, "text/plain; charset=utf-8", err.Error())
	_ = resp.Write(w)
}

// clientHelloSNI extracts the SNI hostname from the first TLS ClientHello record
// without consuming the buffered bytes, so they can be replayed afterwards.
func clientHelloSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 22 { // handshake record
		return "", errors.New("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 4 || recLen > 1<<20 {
		return "", errors.New("invalid TLS record length")
	}

	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return "", err
	}
	if len(buf) < 44 || buf[5] != 1 { // handshake type ClientHello
		return "", errors.New("not a ClientHello")
	}

	// Record header (5) + handshake type (1) + handshake length (3) + client
	// version (2) + random (32) => session-id length at index 43.
	p := 43
	sidLen := int(buf[p])
	p++
	if p+sidLen > len(buf) {
		return "", errors.New("short ClientHello (session id)")
	}
	p += sidLen

	// cipher suites
	if p+2 > len(buf) {
		return "", errors.New("short ClientHello (cipher suites)")
	}
	csLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	if p+csLen > len(buf) {
		return "", errors.New("short ClientHello (cipher suite data)")
	}
	p += csLen

	// compression methods
	if p+1 > len(buf) {
		return "", errors.New("short ClientHello (compression)")
	}
	cmLen := int(buf[p])
	p++
	if p+cmLen > len(buf) {
		return "", errors.New("short ClientHello (compression data)")
	}
	p += cmLen

	// extensions
	if p+2 > len(buf) {
		return "", errors.New("no SNI extension")
	}
	extLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	end := p + extLen
	if end > len(buf) {
		end = len(buf)
	}

	for p+4 <= end {
		extType := int(buf[p])<<8 | int(buf[p+1])
		extLen2 := int(buf[p+2])<<8 | int(buf[p+3])
		p += 4
		if extType == 0 { // server_name (SNI)
			if p+2 > end {
				return "", errors.New("short SNI extension")
			}
			listLen := int(buf[p])<<8 | int(buf[p+1])
			p += 2
			listEnd := p + listLen
			if listEnd > end {
				listEnd = end
			}
			for p+3 <= listEnd {
				nameType := buf[p]
				p++
				nameLen := int(buf[p])<<8 | int(buf[p+1])
				p += 2
				if p+nameLen > listEnd {
					return "", errors.New("short SNI hostname")
				}
				if nameType == 0 {
					return string(buf[p : p+nameLen]), nil
				}
				p += nameLen
			}
			return "", errors.New("SNI has no hostname")
		}
		p += extLen2
	}
	return "", errors.New("no SNI extension")
}
