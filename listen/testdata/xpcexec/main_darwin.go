//go:build darwin && cgo

// Command xpcexec is the production-listener side of the exec-in-place fixture.
package main

import (
	"context"
	"fmt"
	"os"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: xpcexec xpc:service expected-program observed-file effect-file")
		os.Exit(2)
	}
	listener, err := listen.Listen(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	need := identity.Need{User: identity.ProofKernel, Process: identity.ProofKernel, Path: identity.ProofBound}
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		go func() {
			call, receiveErr := listen.ReceiveFramed(context.Background(), conn, need, listen.DefaultMaxFrame)
			if receiveErr != nil {
				return
			}
			defer call.Close()
			peer, peerErr := call.Peer()
			if peerErr != nil {
				return
			}
			path, pathErr := peer.Path.AtLeast(identity.ProofBound)
			process, processErr := peer.Process.AtLeast(identity.ProofKernel)
			if pathErr != nil || processErr != nil {
				return
			}
			observation := fmt.Sprintf("pid=%d path=%s path_proof=%s process_proof=%s\n",
				process.PID, path, peer.Path.Proof(), peer.Process.Proof())
			if err := os.WriteFile(os.Args[3], []byte(observation), 0o600); err != nil {
				return
			}
			if path != os.Args[2] {
				return
			}
			if err := os.WriteFile(os.Args[4], call.Frame, 0o600); err != nil {
				return
			}
			_ = call.Reply(call.Frame)
		}()
	}
}
