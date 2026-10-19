//go:build !darwin || !cgo

package identity

import (
	"errors"
	"testing"
)

func TestBindStartedProcessUnsupported(t *testing.T) {
	if b, err := BindStartedProcess(nil); b != nil || !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("unsupported b=%v err=%v", b, err)
	}
}
