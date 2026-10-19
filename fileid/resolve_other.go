//go:build !windows && !darwin && !linux

package fileid

import (
	"context"
	"errors"
)

var errNoWalk = errors.New("fileid: no file identity walk on this platform")

func open(context.Context, string, Options) (Handle, error) { return Handle{}, errNoWalk }

func withoutStream(abs string) (string, error) { return abs, nil }

func spellingLocal(path string) error { return localPath(path) }

func stillAt(Handle) (bool, error) { return false, errNoWalk }

func beneath(Handle, []string, Options) (Handle, error) { return Handle{}, errNoWalk }

func createExclusive(Handle, string) (Handle, error) { return Handle{}, errNoWalk }

func leafName(Handle, string) (string, bool, error) { return "", false, errNoWalk }

func openByID(context.Context, StoredFileID) (FileID, bool) { return FileID{}, false }
