// Package socks5 reads and writes the SOCKS version 5 wire format
// (RFC 1928) and its username/password sub-negotiation (RFC 1929).
// It knows nothing about networking policy: it only turns bytes into
// values and values into bytes.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// Version is the first byte of every SOCKS5 message.
const Version = 0x05

// Authentication methods (RFC 1928, section 3).
const (
	MethodNoAuth       byte = 0x00
	MethodUserPass     byte = 0x02
	MethodNoAcceptable byte = 0xFF
)

// Commands (RFC 1928, section 4).
const (
	CmdConnect   byte = 0x01
	CmdBind      byte = 0x02
	CmdAssociate byte = 0x03
)

// Address types (RFC 1928, section 5).
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

// Reply codes (RFC 1928, section 6).
const (
	RepSucceeded           byte = 0x00
	RepGeneralFailure      byte = 0x01
	RepNotAllowed          byte = 0x02
	RepNetworkUnreachable  byte = 0x03
	RepHostUnreachable     byte = 0x04
	RepConnectionRefused   byte = 0x05
	RepTTLExpired          byte = 0x06
	RepCommandNotSupported byte = 0x07
	RepAddrNotSupported    byte = 0x08
)

// Errors returned when the client sends something this package rejects.
var (
	ErrVersion     = errors.New("socks5: unsupported version")
	ErrAddrType    = errors.New("socks5: unsupported address type")
	ErrEmptyDomain = errors.New("socks5: empty domain name")
	ErrBadDomain   = errors.New("socks5: invalid domain name")
)

// ReadGreeting reads the client's first message:
//
//	+-----+----------+----------+
//	| VER | NMETHODS | METHODS  |
//	+-----+----------+----------+
//	|  1  |    1     | 1 to 255 |
//	+-----+----------+----------+
//
// and returns the authentication methods the client offers.
func ReadGreeting(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// WriteMethod tells the client which authentication method was chosen.
func WriteMethod(w io.Writer, method byte) error {
	_, err := w.Write([]byte{Version, method})
	return err
}

// ReadUserPass reads an RFC 1929 request:
//
//	+-----+------+----------+------+----------+
//	| VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+-----+------+----------+------+----------+
//	|  1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+-----+------+----------+------+----------+
func ReadUserPass(r io.Reader) (user, pass string, err error) {
	var ver [1]byte
	if _, err = io.ReadFull(r, ver[:]); err != nil {
		return "", "", err
	}
	if ver[0] != 0x01 {
		return "", "", fmt.Errorf("socks5: bad auth version %d", ver[0])
	}
	if user, err = readShortString(r); err != nil {
		return "", "", err
	}
	if pass, err = readShortString(r); err != nil {
		return "", "", err
	}
	return user, pass, nil
}

// WriteAuthStatus answers an RFC 1929 request. Any status other than
// 0x00 tells the client it failed, and the server must close.
func WriteAuthStatus(w io.Writer, ok bool) error {
	status := byte(0x01)
	if ok {
		status = 0x00
	}
	_, err := w.Write([]byte{0x01, status})
	return err
}

// readShortString reads a one-byte length followed by that many bytes.
func readShortString(r io.Reader) (string, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	buf := make([]byte, n[0])
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// Request is what the client asks the proxy to do, and where.
type Request struct {
	Cmd  byte
	Host string // an IP address, or a domain name for the proxy to resolve
	Port uint16
}

// Addr returns "host:port", ready for net.Dial. JoinHostPort adds the
// brackets an IPv6 address needs ("[::1]:80").
func (r Request) Addr() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// ReadRequest reads the client's request:
//
//	+-----+-----+-------+------+----------+----------+
//	| VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+-----+-----+-------+------+----------+----------+
//	|  1  |  1  | X'00' |  1   | Variable |    2     |
//	+-----+-----+-------+------+----------+----------+
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, err
	}
	if hdr[0] != Version {
		return Request{}, fmt.Errorf("%w: %d", ErrVersion, hdr[0])
	}
	req := Request{Cmd: hdr[1]}

	switch hdr[3] {
	case AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return Request{}, err
		}
		req.Host = netip.AddrFrom4(ip).String()
	case AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return Request{}, err
		}
		req.Host = netip.AddrFrom16(ip).String()
	case AtypDomain:
		name, err := readShortString(r)
		if err != nil {
			return Request{}, err
		}
		if name == "" {
			return Request{}, ErrEmptyDomain
		}
		if !validDomain(name) {
			return Request{}, fmt.Errorf("%w: %q", ErrBadDomain, name)
		}
		req.Host = name
	default:
		return Request{}, fmt.Errorf("%w: %d", ErrAddrType, hdr[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Request{}, err
	}
	req.Port = binary.BigEndian.Uint16(port[:])
	return req, nil
}

// validDomain accepts only the characters a hostname can have. The
// wire format allows any byte, so without this check a client could
// send "[0" or "a:b" and produce an address net.Dial cannot parse.
// (Found by FuzzReadRequest.)
func validDomain(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// WriteReply sends the server's answer:
//
//	+-----+-----+-------+------+----------+----------+
//	| VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+-----+-----+-------+------+----------+----------+
//	|  1  |  1  | X'00' |  1   | Variable |    2     |
//	+-----+-----+-------+------+----------+----------+
//
// bound is the proxy's own address for the outgoing connection; when it
// is nil (for example on failure), 0.0.0.0:0 is sent.
func WriteReply(w io.Writer, rep byte, bound net.Addr) error {
	ip, port := net.IPv4zero, 0
	if a, ok := bound.(*net.TCPAddr); ok {
		ip, port = a.IP, a.Port
	}
	buf := []byte{Version, rep, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, AtypIPv4)
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, AtypIPv6)
		buf = append(buf, ip.To16()...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	_, err := w.Write(buf)
	return err
}
