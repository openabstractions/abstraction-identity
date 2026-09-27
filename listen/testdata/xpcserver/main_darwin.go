//go:build darwin && cgo

// Command xpcserver is a disposable cross-language test fixture.
package main

import (
	"context"
	"fmt"
	"os"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: xpcserver xpc:service")
		os.Exit(2)
	}
	l, err := listen.Listen(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer l.Close()
	need := identity.Need{User: identity.ProofKernel, Process: identity.ProofKernel, Path: identity.ProofBound}
	for {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			fmt.Fprintln(os.Stderr, acceptErr)
			return
		}
		go func() {
			call, receiveErr := listen.ReceiveFramed(context.Background(), conn, need, listen.DefaultMaxFrame)
			if receiveErr != nil {
				return
			}
			defer call.Close()
			if string(call.Frame) == "close-listener" {
				_ = l.Close()
				return
			}
			_ = call.Reply(call.Frame)
		}()
	}
}
