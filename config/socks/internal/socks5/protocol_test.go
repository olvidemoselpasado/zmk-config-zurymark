package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestReadRequest(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    Request
		wantErr error
	}{
		{
			name: "ipv4",
			in:   []byte{5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90},
			want: Request{Cmd: CmdConnect, Host: "127.0.0.1", Port: 8080},
		},
		{
			name: "domain",
			in:   append([]byte{5, 1, 0, 3, 11}, append([]byte("example.com"), 0, 80)...),
			want: Request{Cmd: CmdConnect, Host: "example.com", Port: 80},
		},
		{
			name: "ipv6",
			in:   []byte{5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0xBB},
			want: Request{Cmd: CmdConnect, Host: "::1", Port: 443},
		},
		{name: "socks4", in: []byte{4, 1, 0, 1}, wantErr: ErrVersion},
		{name: "unknown address type", in: []byte{5, 1, 0, 9}, wantErr: ErrAddrType},
		{name: "empty domain", in: []byte{5, 1, 0, 3, 0, 0, 80}, wantErr: ErrEmptyDomain},
		{name: "domain with bracket (found by fuzzing)", in: []byte("\x05\x01\x00\x03\x02[0\x00\x50"), wantErr: ErrBadDomain},
		{name: "truncated", in: []byte{5, 1, 0, 1, 127, 0}, wantErr: io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadRequest(bytes.NewReader(tt.in))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRequestAddr(t *testing.T) {
	r := Request{Host: "::1", Port: 80}
	if got := r.Addr(); got != "[::1]:80" {
		t.Errorf("Addr() = %q, want %q", got, "[::1]:80")
	}
}

func TestWriteReply(t *testing.T) {
	var buf bytes.Buffer
	bound := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1080}
	if err := WriteReply(&buf, RepSucceeded, bound); err != nil {
		t.Fatal(err)
	}
	want := []byte{5, 0, 0, 1, 10, 0, 0, 2, 0x04, 0x38}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("got % x, want % x", buf.Bytes(), want)
	}
}

func TestReadGreeting(t *testing.T) {
	methods, err := ReadGreeting(bytes.NewReader([]byte{5, 2, MethodNoAuth, MethodUserPass}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(methods, []byte{MethodNoAuth, MethodUserPass}) {
		t.Errorf("methods = % x", methods)
	}
}

// FuzzReadRequest feeds random bytes to the parser. Whatever arrives
// from the network, ReadRequest must never panic, and whatever it
// accepts must be a usable address.
func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Add(append([]byte{5, 1, 0, 3, 3}, []byte("a.b\x00\x50")...))
	f.Add([]byte{5, 1, 0, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ReadRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if req.Host == "" {
			t.Fatalf("accepted a request with no host: % x", data)
		}
		if _, _, err := net.SplitHostPort(req.Addr()); err != nil {
			t.Fatalf("Addr() %q is not host:port: %v", req.Addr(), err)
		}
	})
}
