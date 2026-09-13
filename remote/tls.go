// Package remote supplies explicitly trusted, mutually authenticated TLS streams
// for the shared frame protocol. Certificate identity belongs to the remote
// trust domain. Hosts map it to authorized caller scopes at their boundary.
package remote

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

const Protocol = "oa-framed/1"
const Transport = "oa-framed-mtls@1"

var ErrTrust = errors.New("remote: authentication or trust configuration refused")

// Client returns the ordinary shared framing client over an authenticated TLS
// dialer. Registration supplies address, ServerName, trust roots and client key.
// Keep certificate keys and callbacks immutable while this client is in use.
// No endpoint discovery, system-root fallback, redirect or retry occurs here.
func Client(address string, config *tls.Config, timeout time.Duration, maxFrame uint32) (listen.FrameClient, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return listen.FrameClient{}, fmt.Errorf("%w: explicit host:port required", ErrTrust)
	}
	if config == nil || config.InsecureSkipVerify || config.ServerName == "" || config.RootCAs == nil ||
		(len(config.Certificates) == 0 && config.GetClientCertificate == nil) {
		return listen.FrameClient{}, fmt.Errorf("%w: server name, roots and client credential required", ErrTrust)
	}
	c := config.Clone()
	c.RootCAs = config.RootCAs.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{Protocol}
	// A fresh handshake rechecks the configured certificate trust on every call.
	c.ClientSessionCache = nil
	if c.MaxVersion != 0 && c.MaxVersion < c.MinVersion {
		return listen.FrameClient{}, fmt.Errorf("%w: TLS 1.3 required", ErrTrust)
	}
	dial := func(ctx context.Context, selected string) (net.Conn, error) {
		if selected != address {
			return nil, fmt.Errorf("%w: endpoint differs from trusted registration", ErrTrust)
		}
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, c)
		if deadline, ok := ctx.Deadline(); ok {
			if err = conn.SetDeadline(deadline); err != nil {
				raw.Close()
				return nil, err
			}
		}
		if err = conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("%w: %w", ErrTrust, err)
		}
		state := conn.ConnectionState()
		if state.NegotiatedProtocol != Protocol || len(state.VerifiedChains) == 0 {
			raw.Close()
			return nil, fmt.Errorf("%w: frame protocol or verified server chain missing", ErrTrust)
		}
		return &ownedStream{Conn: conn, raw: raw}, nil
	}
	return listen.FrameClient{Endpoint: address, Timeout: timeout, MaxFrame: maxFrame, Dialer: dial}, nil
}

// TLS Close can start a fresh close-notify write timeout. Frame ownership ends
// by closing TCP directly, keeping cleanup inside the existing call budget.
type ownedStream struct {
	*tls.Conn
	raw net.Conn
}

func (c *ownedStream) Close() error { return c.raw.Close() }

// Peer is receiving-side verified certificate evidence. Key identifies its public
// key across certificate renewal. Policy decides whether that key maps to an
// existing logical caller; accepting a CA alone grants no capability authority.
type Peer struct {
	Certificate *x509.Certificate
	Key         [32]byte
}

func peer(state tls.ConnectionState) (Peer, error) {
	if state.NegotiatedProtocol != Protocol || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return Peer{}, ErrTrust
	}
	cert := state.PeerCertificates[0]
	return Peer{Certificate: cert, Key: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}, nil
}
