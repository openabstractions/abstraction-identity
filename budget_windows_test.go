//go:build windows

package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// ID-V1: one account runs at most maxVerificationsPerAccount first-time code
// verifications at once. The next one of that account is refused with the
// reason, and another account still verifies.
func TestCodeVerificationsPerAccountAreBounded(t *testing.T) {
	entered := make(chan string, maxVerificationsPerAccount+1)
	release := make(chan struct{})
	countVerifications(t, func(_ windows.Handle, path string, _ *Options) (Code, Proof, error) {
		entered <- path
		<-release
		return Code{Status: path}, ProofUnsigned, nil
	})
	proc, pid, started := selfInstance(t)
	path := mustExe(t)
	var done sync.WaitGroup
	defer func() { close(release); done.Wait() }()
	verify := func(image, account string) {
		done.Add(1)
		go func() {
			defer done.Done()
			if _, _, _, err := verifyProcessImageAt(proc, pid, started, image, account, nil); err != nil {
				t.Errorf("verify %s for %s: %v", image, account, err)
			}
		}()
	}
	const account = "S-1-5-21-1-2-3-1001"
	for i := range maxVerificationsPerAccount {
		verify(fmt.Sprintf("%s.%d", path, i), account)
	}
	for range maxVerificationsPerAccount {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the account's verifications did not all start")
		}
	}
	_, verdict, _, err := verifyProcessImageAt(proc, pid, started, path+".over", account, nil)
	if !errors.Is(err, errVerificationBudget) || verdict != ProofNone {
		t.Fatalf("a verification over the account's bound: %v, %v; want errVerificationBudget at none", verdict, err)
	}
	verify(path+".other", "S-1-5-21-1-2-3-1002")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("another account could not verify while the first was at its bound")
	}
}
