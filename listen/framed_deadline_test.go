package listen

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// Models a timer whose deadline elapsed before its cancellation callback ran.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestFrameErrorDeadlineCallbackOrdering(t *testing.T) {
	ctx := pendingDeadlineContext{context.Background(), time.Now().Add(-time.Second)}
	if e := frameError(ctx, os.ErrDeadlineExceeded); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if e := frameError(ctx, io.EOF); !errors.Is(e, io.EOF) {
		t.Fatal("non-timeout replaced", e)
	}
	ctx.deadline = time.Now().Add(time.Hour)
	if e := frameError(ctx, os.ErrDeadlineExceeded); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("unexpired context replaced timeout", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e := frameError(canceled, os.ErrDeadlineExceeded); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
