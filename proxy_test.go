package main

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// buildClientHello constructs a minimal, valid TLS ClientHello with the given
// SNI hostname, used to exercise the SNI parser.
func buildClientHello(sni string) []byte {
	// handshake body: client_version(2) + random(32) + session_id
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session id length 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression: null

	// SNI extension: type 0, data = server_name_list
	sniData := []byte{0x00, byte(len(sni) + 3)} // list length
	sniData = append(sniData, 0x00, 0x00, byte(len(sni)))
	sniData = append(sniData, []byte(sni)...)
	ext := []byte{0x00, 0x00, byte(len(sniData) >> 8), byte(len(sniData) & 0xff)}
	ext = append(ext, sniData...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)&0xff))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body) & 0xff)}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs) & 0xff)}
	rec = append(rec, hs...)
	return rec
}

func TestClientHelloSNI(t *testing.T) {
	for _, host := range []string{"flow.google.com", "www.gstatic.com", "example.com"} {
		br := bufio.NewReader(bytes.NewReader(buildClientHello(host)))
		sni, err := clientHelloSNI(br)
		if err != nil {
			t.Fatalf("clientHelloSNI(%q): %v", host, err)
		}
		if sni != host {
			t.Fatalf("clientHelloSNI(%q) = %q", host, sni)
		}
	}
}

func TestClientHelloSNI_NoSNI(t *testing.T) {
	// Same structure but the loop just won't find an SNI if the extension is
	// absent; feed a truncated ClientHello with no extensions.
	data := buildClientHello("x")
	// Strip the extensions length + extension bytes (last 2 + len(ext) bytes).
	data = data[:len(data)-2-2] // remove ext length (2) and a 2-byte extension stub is not present; adjust below
	// Simpler: build a ClientHello with zero extensions.
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, 0x00, 0x00) // zero extensions
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body) & 0xff)}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs) & 0xff)}
	rec = append(rec, hs...)

	br := bufio.NewReader(bytes.NewReader(rec))
	if _, err := clientHelloSNI(br); err == nil {
		t.Fatal("expected error for ClientHello without SNI")
	}
}

func newTestServer() *server {
	return newServer(defaultConfig(), log.New(io.Discard, "", 0))
}

func TestPatchResponse_Applies(t *testing.T) {
	s := newTestServer()
	src := `if(!Qa())return this.router.navigateByUrl("/unsupported-country");if(!Rb())return n("/age-restricted");`

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Length":   []string{strconv.Itoa(len(src))},
			"Content-Encoding": []string{"gzip"},
			"ETag":             []string{`"abc"`},
		},
		Body: io.NopCloser(strings.NewReader(src)),
	}
	req := &http.Request{
		URL:        &url.URL{Scheme: "https", Host: TARGET_HOST, Path: "/x/AiSandboxAngularFrontend/m=_b"},
		RemoteAddr: "192.168.1.10:5555",
	}

	out := s.patchResponse(req, resp)
	body, _ := io.ReadAll(out.Body)
	if !strings.Contains(string(body), "if(false)return this.router.navigateByUrl") {
		t.Fatalf("bundle was not patched:\n%s", body)
	}
	if out.Header.Get("ETag") != "" {
		t.Fatal("ETag should be removed after patching")
	}
	if out.Header.Get("Content-Encoding") != "" {
		t.Fatal("Content-Encoding should be removed after patching")
	}
	if out.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", out.Header.Get("Cache-Control"))
	}
}

func TestPatchResponse_MismatchPassesThrough(t *testing.T) {
	s := newTestServer()
	src := "function unrelated() { return 1; }"

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(src)),
	}
	req := &http.Request{
		URL:        &url.URL{Scheme: "https", Host: TARGET_HOST, Path: "/x/AiSandboxAngularFrontend/m=_b"},
		RemoteAddr: "192.168.1.10:5555",
	}

	out := s.patchResponse(req, resp)
	body, _ := io.ReadAll(out.Body)
	if string(body) != src {
		t.Fatalf("mismatch should pass original body through, got:\n%s", body)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run.LastError == "" {
		t.Fatal("expected an error to be recorded on mismatch")
	}
}

func TestPatchResponse_SkipsNonTarget(t *testing.T) {
	s := newTestServer()
	src := "hello"
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(src))}
	req := &http.Request{
		URL:        &url.URL{Scheme: "https", Host: "other.google.com", Path: "/foo.js"},
		RemoteAddr: "192.168.1.10:5555",
	}
	out := s.patchResponse(req, resp)
	body, _ := io.ReadAll(out.Body)
	if string(body) != src {
		t.Fatal("non-target response should be untouched")
	}
}
