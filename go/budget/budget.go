// Package budget derives the time budget of one step from its caller's
// deadline. A step a person waits for, or one that writes durable state,
// takes the time its caller allows, so it finishes under load instead of
// timing out at a short fixed constant while the caller would still wait.
package budget

import (
	"context"
	"errors"
	"time"
)

// Within returns the context for one step.
//
//   - A caller deadline with at least floor remaining bounds the step.
//   - A caller without a deadline gives the step fallback.
//   - A caller deadline with less than floor remaining gives the step floor
//     from now; the caller's explicit cancellation still ends the step.
//
// floor is the least time the step needs on a busy machine; fallback bounds
// a step whose caller set no deadline.
func Within(ctx context.Context, floor, fallback time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithTimeout(ctx, fallback)
	}
	if time.Until(deadline) >= floor {
		return context.WithCancel(ctx)
	}
	step, cancel := context.WithTimeout(context.WithoutCancel(ctx), floor)
	cancelled := func() bool {
		return ctx.Err() != nil && !errors.Is(context.Cause(ctx), context.DeadlineExceeded)
	}
	if cancelled() {
		// AfterFunc runs its function on its own goroutine for a context
		// that is already done; a caller cancelled before this call gets a
		// step that is already ended.
		cancel()
		return step, cancel
	}
	stop := context.AfterFunc(ctx, func() {
		if cancelled() {
			cancel()
		}
	})
	return step, func() {
		stop()
		cancel()
	}
}
