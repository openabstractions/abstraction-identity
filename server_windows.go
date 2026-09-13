package identity

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

type windowsServerBinding struct {
	windowsBinding
	sid string
}

func serverPrincipal(proc windows.Handle) (User, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return User{}, err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return User{}, err
	}
	return User{Kind: "windows", SID: u.User.Sid.String(), UID: -1, GID: -1}, nil
}

func bindServerHandle(h Handle, opts *Options) (binder, *Peer, error) {
	pipe := windows.Handle(h)
	var flags uint32
	if err := windows.GetNamedPipeInfo(pipe, &flags, nil, nil, nil); err != nil {
		return nil, nil, err
	}
	if flags&windows.PIPE_SERVER_END != 0 {
		return nil, nil, ErrUnsupportedConn
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoBinding, err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoBinding, err)
	}
	b := &windowsServerBinding{windowsBinding: windowsBinding{pipe: pipe, proc: proc, pid: pid}}
	fail := func(err error) (binder, *Peer, error) { b.release(); return nil, nil, err }
	b.started, err = processStartTime(proc)
	if err != nil {
		return fail(err)
	}
	if b.started.After(opts.connectedAt()) {
		return fail(ErrPeerMoved)
	}
	u, err := serverPrincipal(proc)
	if err != nil {
		return fail(err)
	}
	b.sid = u.SID
	path, err := processImagePath(proc)
	if err != nil {
		return fail(err)
	}
	if err := b.recheck(); err != nil {
		return fail(err)
	}
	p := &Peer{Platform: "windows", Transport: "npipe", ObservedAt: time.Now(),
		User:    attr("user", u, ProofBound, "server process primary token read through retained process handle; rechecked before I/O"),
		Process: attr("process", Process{PID: int(pid), StartTime: b.started}, ProofKernel, "pipe server PID with retained process creation time"),
		Path:    attr("path", path, ProofBound, "image path read through retained server process handle"),
		Package: unknown[string]("package", "not requested"), Code: unknown[Code]("code", "not requested")}
	return b, p, nil
}

func (b *windowsServerBinding) recheck() error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(b.pipe, &pid); err != nil {
		return fmt.Errorf("%w: %v", ErrNoBinding, err)
	}
	if pid != b.pid {
		return ErrPeerMoved
	}
	u, err := serverPrincipal(b.proc)
	if err != nil {
		return err
	}
	if u.SID != b.sid {
		return ErrPeerMoved
	}
	return nil
}
