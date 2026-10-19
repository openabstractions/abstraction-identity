package listen

import (
	"context"
	"sync/atomic"
)

// outgoingGuard is the process's check of each frame it sends, or nil.
var outgoingGuard atomic.Pointer[func([]byte) error]

// GuardOutgoingFrames installs guard, a process-wide check every frame a
// FrameClient sends passes first. A non-nil error refuses the frame before any
// connection, and the call returns that error. A program uses it to restrict
// itself, such as the Panel serving its developer page, which makes no
// change only the person's own window may make. Nil removes the guard.
func GuardOutgoingFrames(guard func(frame []byte) error) {
	if guard == nil {
		outgoingGuard.Store(nil)
		return
	}
	outgoingGuard.Store(&guard)
}

func checkOutgoing(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if guard := outgoingGuard.Load(); guard != nil {
		return (*guard)(frame)
	}
	return nil
}
