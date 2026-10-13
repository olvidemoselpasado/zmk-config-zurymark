package proxy_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"socks/internal/proxy"
	"socks/internal/socks5"
)

// startProxy runs a proxy on a free localhost port for the duration of
// the test and returns its address.
func startProxy(t *testing.T, creds map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") // port 0: the OS picks a free one
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &proxy.Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Credentials: creds}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

// clientVia returns an HTTP client that sends everything through the proxy.
func clientVia(proxyURL *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

func backend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hola desde el destino")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPThroughProxy(t *testing.T) {
	target := backend(t)
	addr := startProxy(t, nil)

	// "localhost" instead of 127.0.0.1: with socks5h the proxy, not the
	// client, resolves the name (address type 0x03 on the wire).
	u := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	resp, err := clientVia(&url.URL{Scheme: "socks5h", Host: addr}).Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hola desde el destino" {
		t.Errorf("body = %q", body)
	}
}

func TestAuthentication(t *testing.T) {
	target := backend(t)
	addr := startProxy(t, map[string]string{"ana": "secreto"})

	tests := []struct {
		name   string
		user   *url.Userinfo
		wantOK bool
	}{
		{"right password", url.UserPassword("ana", "secreto"), true},
		{"wrong password", url.UserPassword("ana", "otro"), false},
		{"no credentials", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := clientVia(&url.URL{Scheme: "socks5h", Host: addr, User: tt.user}).Get(target.URL)
			if err == nil {
				resp.Body.Close()
			}
			if gotOK := err == nil; gotOK != tt.wantOK {
				t.Errorf("ok = %v, want %v (err: %v)", gotOK, tt.wantOK, err)
			}
		})
	}
}

// rawRequest speaks SOCKS5 by hand and returns the reply code.
func rawRequest(t *testing.T, proxyAddr string, req []byte) byte {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, socks5.MethodNoAuth})
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatal(err)
	}
	c.Write(req)
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func TestConnectionRefused(t *testing.T) {
	addr := startProxy(t, nil)

	// Grab a free port and close it, so nothing is listening there.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	req := []byte{5, socks5.CmdConnect, 0, socks5.AtypIPv4, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if got := rawRequest(t, addr, req); got != socks5.RepConnectionRefused {
		t.Errorf("reply = %#x, want %#x", got, socks5.RepConnectionRefused)
	}
}

func TestUnsupportedCommand(t *testing.T) {
	addr := startProxy(t, nil)
	req := []byte{5, socks5.CmdBind, 0, socks5.AtypIPv4, 127, 0, 0, 1, 0, 80}
	if got := rawRequest(t, addr, req); got != socks5.RepCommandNotSupported {
		t.Errorf("reply = %#x, want %#x", got, socks5.RepCommandNotSupported)
	}
}

// TestRelayIsTransparent sends a large payload through the tunnel to an
// echo server and checks every byte comes back unchanged.
func TestRelayIsTransparent(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	addr := startProxy(t, nil)

	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	p := echo.Addr().(*net.TCPAddr).Port
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(p >> 8), byte(p)})
	io.ReadFull(c, make([]byte, 10))

	payload := bytes.Repeat([]byte("gopher "), 100_000) // 700 KB
	go func() {
		c.Write(payload)
		c.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes back, want %d", len(got), len(payload))
	}
}
