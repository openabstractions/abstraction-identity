package listen

import (
	"io"
	"sync"
)

// CallAdmission bounds handlers from acceptance through their return. Transport
// close and handshake failure do not release the handler's admission.
type CallAdmission chan struct{}

// NewCallAdmission constructs a nonblocking handler bound. A limit below one is
// a programming error; each host supplies its existing finite limit.
func NewCallAdmission(limit int) CallAdmission {
	if limit < 1 {
		panic("listen: call admission limit must be positive")
	}
	return make(CallAdmission, limit)
}

// Take claims a slot before the caller starts a handler. On success the caller
// must defer release until that handler returns. Release is idempotent. When
// full, Take closes the refused connection and starts no handler. It retains
// the concrete connection unchanged, including its identity and transport APIs.
func (a CallAdmission) Take(connection io.Closer) (release func(), admitted bool) {
	select {
	case a <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-a }) }, true
	default:
		//unchecked: the connection is refused; no caller remains to receive a close error
		connection.Close()
		return nil, false
	}
}
