package fileid

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// FromFile describes a duplicate of an already-open native descriptor. The
// caller retains f; the returned Handle owns its duplicate. It reads canonical
// identity and final-path facts, refuses a name-surrogate object, and performs
// no ancestor walk or authority check. Its access/sharing stay those of f.
func FromFile(ctx context.Context, f *os.File) (Handle, error) {
	if f == nil {
		return Handle{}, ErrNoFile
	}
	if err := ctx.Err(); err != nil {
		return Handle{}, err
	}
	var duplicate windows.Handle
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, windows.Handle(f.Fd()), self, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return Handle{}, err
	}
	tag, err := readAttributeTag(duplicate)
	if err != nil || isLink(tag) {
		if err == nil {
			err = ErrLink
		}
		return Handle{}, errors.Join(err, windows.CloseHandle(duplicate))
	}
	h, err := describe(duplicate, f.Name())
	if err != nil {
		return Handle{}, err
	}
	if err := ctx.Err(); err != nil {
		return Handle{}, errors.Join(err, h.Close())
	}
	return h, nil
}
