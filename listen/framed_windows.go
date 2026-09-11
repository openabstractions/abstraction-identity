package listen

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func dialFramed(ctx context.Context, name string) (net.Conn, error) {
	if !strings.HasPrefix(name, `\\.\pipe\`) || len(name) <= len(`\\.\pipe\`) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errors.New("expected local named pipe")}
	}
	return dialPipeContext(ctx, name, false)
}
func dialPipeContext(ctx context.Context, name string, legacy bool) (net.Conn, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, identifyOnly|windows.FILE_FLAG_OVERLAPPED, 0)
		if err == nil {
			if ctx.Err() != nil {
				windows.CloseHandle(h)
				return nil, ctx.Err()
			}
			return fileConn{os.NewFile(uintptr(h), name)}, nil
		}
		if !errors.Is(err, errPipeBusy) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		if legacy {
			if r, _, err := waitNamedPipe.Call(uintptr(unsafe.Pointer(n)), busyWait); r == 0 {
				return nil, &fs.PathError{Op: "open", Path: name, Err: err}
			}
			continue
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
