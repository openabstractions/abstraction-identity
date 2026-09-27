//go:build darwin && cgo

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: xpcstress service server-program uid")
	}
	uid, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clients := make([]*identity.XPCClient, 0, 128)
	for len(clients) < cap(clients) {
		client, openErr := identity.OpenXPCClient(ctx, os.Args[1], os.Args[2], uint32(uid), 1024)
		if openErr != nil {
			panic(fmt.Sprintf("open %d: %v", len(clients), openErr))
		}
		clients = append(clients, client)
	}
	extra, admissionErr := identity.OpenXPCClient(ctx, os.Args[1], os.Args[2], uint32(uid), 1024)
	if admissionErr == nil {
		extra.Close()
		panic("session capacity did not refuse client 129")
	}
	for _, client := range clients {
		client.Close()
	}
	var recovered *identity.XPCClient
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		recovered, err = identity.OpenXPCClient(ctx, os.Args[1], os.Args[2], uint32(uid), 1024)
		if err == nil {
			break
		}
	}
	if recovered == nil {
		panic(fmt.Sprintf("capacity did not recover: %v", err))
	}
	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	started := time.Now()
	_, _, err = recovered.Call(callCtx, []byte("close-listener"), false)
	elapsed := time.Since(started)
	callCancel()
	recovered.Close()
	if !errors.Is(err, net.ErrClosed) {
		panic(fmt.Sprintf("listener close = %v after %s, want net.ErrClosed", err, elapsed))
	}
	if elapsed >= time.Second {
		panic(fmt.Sprintf("listener close took %s, want under 1s", elapsed))
	}
	fmt.Printf("admission refusal=%q; capacity recovered; listener close=%v in %s\n", admissionErr, err, elapsed)
}
