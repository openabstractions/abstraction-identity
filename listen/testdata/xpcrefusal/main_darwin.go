//go:build darwin && cgo

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: probe server|client service server-path marker")
	}
	switch os.Args[1] {
	case "server":
		serve()
	case "client":
		client()
	default:
		panic("unknown mode")
	}
}

func serve() {
	l, err := listen.Listen("xpc:" + os.Args[2])
	if err != nil {
		panic(err)
	}
	defer l.Close()
	if err := os.WriteFile(os.Args[4]+".ready", []byte("ready"), 0600); err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			call, err := listen.ReceiveFramed(context.Background(), c, identity.Need{User: identity.ProofSigned}, 1024)
			if err != nil {
				fmt.Fprintln(os.Stderr, "receiver:", err)
				return
			}
			defer call.Close()
			if err := os.WriteFile(os.Args[4]+".dispatched", call.Frame, 0600); err != nil {
				panic(err)
			}
			_ = call.Reply(call.Frame)
		}()
	}
}

func client() {
	uid, err := strconv.Atoi(os.Getenv("OA_TEST_UID"))
	if err != nil {
		panic(err)
	}
	c := listen.FrameClient{Endpoint: "xpc:" + os.Args[2], Timeout: 5 * time.Second, MaxFrame: 1024,
		Server: &listen.ServerExpectation{Principal: identity.User{Kind: "posix", UID: uid}, Program: os.Args[3]}}
	for _, oneWay := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		var err error
		if oneWay {
			err = c.WriteFrameContext(ctx, []byte("forbidden-effect"))
		} else {
			_, err = c.ExchangeFrameContext(ctx, []byte("forbidden-effect"))
		}
		cancel()
		var refusal *listen.ProofRefusal
		if !errors.Is(err, listen.ErrCallerProofUnmet) || !errors.Is(err, identity.ErrNotProven) ||
			!errors.As(err, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
			panic(fmt.Sprintf("one-way=%v: got %T %v", oneWay, err, err))
		}
		fmt.Printf("one-way=%v: receiver refusal attribute=%s required=%s\n", oneWay, refusal.Attribute, refusal.Required)
	}
}
