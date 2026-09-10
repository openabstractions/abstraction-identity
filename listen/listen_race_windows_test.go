package listen

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
)

// The unix half has proven this since TestConcurrentStartsElectOneListener was
// written; the Windows half asserted it from the flag alone. A starter that
// loses by name rather than by timing is what makes an explicit start
// idempotent, and idempotent is the whole reason a client never has to start a
// helper for itself.
func TestConcurrentStartsElectOneListener(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	const starters = 8
	var wg sync.WaitGroup
	won := make(chan Listener, starters)
	lost := make(chan error, starters)
	start := make(chan struct{})
	for i := 0; i < starters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := Listen(name)
			if err != nil {
				lost <- err
				return
			}
			won <- l
		}()
	}
	close(start)
	wg.Wait()
	close(won)
	close(lost)

	if len(won) != 1 {
		t.Fatalf("%d of %d concurrent starts took the same name", len(won), starters)
	}
	for err := range lost {
		if !errors.Is(err, ErrTaken) {
			t.Fatalf("a losing start failed for the wrong reason: %v", err)
		}
	}
	l := <-won
	defer l.Close()
	c, err := Dial(name)
	if err != nil {
		t.Fatalf("the winning listener is unreachable: %v", err)
	}
	c.Close()
}
