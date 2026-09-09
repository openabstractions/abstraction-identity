package identity

import (
	"errors"
	"net"
	"time"
)

// opaqueConn is a net.Conn that will not give up a handle - the shape of most
// named-pipe wrappers on Windows.
type opaqueConn struct{}

func (opaqueConn) Read([]byte) (int, error)         { return 0, errors.ErrUnsupported }
func (opaqueConn) Write([]byte) (int, error)        { return 0, errors.ErrUnsupported }
func (opaqueConn) Close() error                     { return nil }
func (opaqueConn) LocalAddr() net.Addr              { return nil }
func (opaqueConn) RemoteAddr() net.Addr             { return nil }
func (opaqueConn) SetDeadline(time.Time) error      { return nil }
func (opaqueConn) SetReadDeadline(time.Time) error  { return nil }
func (opaqueConn) SetWriteDeadline(time.Time) error { return nil }
