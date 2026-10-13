// Package proxy runs a SOCKS5 server: it accepts clients, performs the
// handshake with package socks5, dials the target and relays bytes.
package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"socks/internal/socks5"
)

// handshakeTimeout bounds how long a client may take to say what it
// wants. Without it, a client that connects and stays silent would hold
// a goroutine and a file descriptor forever.
const handshakeTimeout = 10 * time.Second

// Server is a SOCKS5 proxy that supports the CONNECT command.
type Server struct {
	// Log receives one line per tunnel and per failed handshake.
	Log *slog.Logger
	// Credentials maps user to password. When nil, no authentication
	// is required: only do that when listening on localhost.
	Credentials map[string]string
	// DialTimeout bounds the connection to the target. Zero means 10s.
	DialTimeout time.Duration
	// Dial opens the outgoing connection. Nil means net.Dialer; tests
	// and policies (allowlists, blocking private networks) replace it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Serve accepts connections on ln until ctx is cancelled. Cancelling
// ctx also closes every open tunnel, so Serve returns promptly.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	log := s.Log.With("client", client.RemoteAddr().String())

	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	req, err := s.handshake(client)
	if err != nil {
		log.Debug("handshake failed", "err", err)
		return
	}
	if req.Cmd != socks5.CmdConnect {
		_ = socks5.WriteReply(client, socks5.RepCommandNotSupported, nil)
		log.Debug("command not supported", "cmd", req.Cmd)
		return
	}

	dctx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	target, err := s.dial(dctx, "tcp", req.Addr())
	cancel()
	if err != nil {
		_ = socks5.WriteReply(client, replyFor(err), nil)
		log.Info("dial failed", "target", req.Addr(), "err", err)
		return
	}
	defer target.Close()

	if err := socks5.WriteReply(client, socks5.RepSucceeded, target.LocalAddr()); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{}) // the tunnel itself may last as long as it needs

	start := time.Now()
	up, down := relay(client, target)
	log.Info("tunnel closed", "target", req.Addr(), "up", up, "down", down, "duration", time.Since(start))
}

// handshake negotiates authentication and reads the request.
func (s *Server) handshake(c net.Conn) (socks5.Request, error) {
	methods, err := socks5.ReadGreeting(c)
	if err != nil {
		return socks5.Request{}, err
	}
	want := socks5.MethodNoAuth
	if s.Credentials != nil {
		want = socks5.MethodUserPass
	}
	if !slices.Contains(methods, want) {
		_ = socks5.WriteMethod(c, socks5.MethodNoAcceptable)
		return socks5.Request{}, errors.New("no acceptable authentication method")
	}
	if err := socks5.WriteMethod(c, want); err != nil {
		return socks5.Request{}, err
	}
	if want == socks5.MethodUserPass {
		user, pass, err := socks5.ReadUserPass(c)
		ok := err == nil && s.checkPassword(user, pass)
		_ = socks5.WriteAuthStatus(c, ok)
		if !ok {
			return socks5.Request{}, errors.New("authentication failed")
		}
	}
	return socks5.ReadRequest(c)
}

// checkPassword compares in constant time, so the response time does
// not reveal how many characters of a guess were right.
func (s *Server) checkPassword(user, pass string) bool {
	want, ok := s.Credentials[user]
	return ok && subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
}

func (s *Server) dialTimeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return 10 * time.Second
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// replyFor translates a dial error into the closest SOCKS5 reply code.
func replyFor(err error) byte {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return socks5.RepHostUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return socks5.RepConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return socks5.RepNetworkUnreachable
	case errors.Is(err, syscall.EAFNOSUPPORT):
		return socks5.RepAddrNotSupported // e.g. an IPv6 target on a proxy without IPv6
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return socks5.RepHostUnreachable
	default:
		return socks5.RepGeneralFailure
	}
}

// relay copies bytes in both directions until both sides finish, and
// returns how many went up (client to target) and down.
func relay(client, target net.Conn) (up, down int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(target, client)
		closeWrite(target) // tell the target the client is done sending
	}()
	down, _ = io.Copy(client, target)
	closeWrite(client)
	wg.Wait()
	return up, down
}

// closeWrite half-closes a TCP connection: we stop sending, but can
// still receive. Other connection types are closed completely.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
