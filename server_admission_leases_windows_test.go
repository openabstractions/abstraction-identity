//go:build windows

package identity

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type inertQueryTargets struct {
	state         [2]string
	writes        int
	fail          map[int]bool
	after         bool
	readFailure   bool
	failReadAfter map[int]bool
	externalAt    map[int]int
	closeFailures int
	closed        int
}

func (f *inertQueryTargets) read(i int) (string, error) {
	if f.readFailure {
		f.readFailure = false
		return "", errors.New("injected read failure")
	}
	return f.state[i], nil
}
func (f *inertQueryTargets) compose(_ int, base string, names []string) (string, error) {
	return base + "+" + strings.Join(names, ","), nil
}
func (f *inertQueryTargets) write(i int, value string) error {
	f.writes++
	if target, ok := f.externalAt[f.writes]; ok {
		f.state[target] = "independent-acl"
	}
	if f.failReadAfter[f.writes] {
		f.readFailure = true
	}
	if f.fail[f.writes] {
		if f.after {
			f.state[i] = value
		}
		return errors.New("injected write failure")
	}
	f.state[i] = value
	return nil
}
func (f *inertQueryTargets) close() error {
	if f.closeFailures > 0 {
		f.closeFailures--
		return errors.New("injected close failure")
	}
	f.closed++
	return nil
}

func inertQueryOwner() (*serverQueryLeases, *inertQueryTargets) {
	f := &inertQueryTargets{state: [2]string{"process-preexisting", "token-preexisting"}}
	return &serverQueryLeases{open: func() (serverQueryTargets, error) { return f, nil }}, f
}

func TestServerQueryLeaseCloseOrders(t *testing.T) {
	for _, names := range [][][]string{{{"a"}, {"b"}}, {{"a"}, {"a"}}, {{"a", "b"}, {"b", "c"}}} {
		for _, first := range []int{0, 1} {
			t.Run(fmt.Sprintf("%v-first%d", names, first), func(t *testing.T) {
				o, f := inertQueryOwner()
				base := f.state
				var close [2]func() error
				for i := range names {
					var err error
					close[i], err = o.acquire(names[i])
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := close[first](); err != nil {
					t.Fatal(err)
				}
				for i := range base {
					want := base[i] + "+" + strings.Join(names[1-first], ",")
					if f.state[i] != want {
						t.Fatalf("live lease: %q want %q", f.state[i], want)
					}
				}
				if err := close[first](); err != nil {
					t.Fatal(err)
				}
				if err := close[1-first](); err != nil {
					t.Fatal(err)
				}
				if f.state != base || f.closed != 1 {
					t.Fatalf("final state=%v closed=%d", f.state, f.closed)
				}
			})
		}
	}
}

func TestServerQueryLeaseApplyFailureRecovery(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("write%d-after%v", failAt, after), func(t *testing.T) {
				o, f := inertQueryOwner()
				base := f.state
				f.fail, f.after = map[int]bool{failAt: true}, after
				if close, err := o.acquire([]string{"a"}); err == nil || close != nil {
					t.Fatal("failed acquisition reported success")
				}
				if f.state != base || o.pending != nil || len(o.counts) != 0 || f.closed != 1 {
					t.Fatalf("rollback state=%v pending=%v counts=%v closed=%d", f.state, o.pending, o.counts, f.closed)
				}
			})
		}
	}
	o, f := inertQueryOwner()
	base := f.state
	f.fail = map[int]bool{2: true, 3: true} // token apply, then process rollback
	if _, err := o.acquire([]string{"a"}); err == nil {
		t.Fatal("partial apply succeeded")
	}
	if o.pending == nil || o.targets == nil || f.closed != 0 {
		t.Fatal("uncertain transition lost recovery custody")
	}
	f.fail = nil
	close, err := o.acquire([]string{"b"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.state[0], "+a") {
		t.Fatal("failed admission grant survived recovery")
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
	if f.state != base {
		t.Fatal("recovered acquisition changed baseline")
	}
}

func TestServerQueryLeaseReleaseFailureCanRetry(t *testing.T) {
	o, f := inertQueryOwner()
	base := f.state
	close, err := o.acquire([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	f.fail = map[int]bool{4: true, 5: true} // token restoration, then process rollback
	if err := close(); err == nil {
		t.Fatal("partial release succeeded")
	}
	if o.pending == nil || o.counts["a"] != 1 || f.closed != 0 {
		t.Fatal("failed release consumed lease or handles")
	}
	f.fail = nil
	if err := close(); err != nil {
		t.Fatal(err)
	}
	if f.state != base || o.pending != nil || f.closed != 1 {
		t.Fatal("release retry did not restore baseline")
	}
}

func TestServerQueryLeaseReadbackAndExternalRollbackRecovery(t *testing.T) {
	o, f := inertQueryOwner()
	base := f.state
	f.failReadAfter = map[int]bool{1: true}
	if _, err := o.acquire([]string{"a"}); err == nil {
		t.Fatal("failed readback accepted")
	}
	if f.state != base || o.pending != nil {
		t.Fatal("readback failure lost restoration")
	}

	o, f = inertQueryOwner()
	f.fail = map[int]bool{2: true}
	f.externalAt = map[int]int{2: 0}
	if _, err := o.acquire([]string{"a"}); err == nil {
		t.Fatal("independent edit accepted")
	}
	if f.state[0] != "independent-acl" || o.pending == nil || f.closed != 0 {
		t.Fatal("independent rollback edit overwritten or recovery lost")
	}
	if _, err := o.acquire([]string{"b"}); err == nil {
		t.Fatal("pending recovery bypassed")
	}
	f.state[0] = o.pending.after[0] // independent owner restores the descriptor
	f.fail, f.externalAt = nil, nil
	close, err := o.acquire([]string{"b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
	if f.state != base {
		t.Fatal("independent-change recovery changed baseline")
	}
}

func TestServerQueryLeaseHandleCleanupCanRetry(t *testing.T) {
	o, f := inertQueryOwner()
	base := f.state
	close, err := o.acquire([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	f.closeFailures = 1
	if err := close(); err == nil {
		t.Fatal("handle failure accepted")
	}
	if f.state != base || o.targets == nil || len(o.counts) != 0 {
		t.Fatal("handle cleanup lost state")
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
	if o.targets != nil || f.closed != 1 {
		t.Fatal("handle cleanup retry failed")
	}
}

func TestServerQueryLeaseIndependentChangeIsPreserved(t *testing.T) {
	o, f := inertQueryOwner()
	close, err := o.acquire([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	owned := f.state
	f.state[1] = "independent-token-acl"
	if err := close(); err == nil {
		t.Fatal("independent change accepted")
	}
	if f.state[0] != owned[0] || f.state[1] != "independent-token-acl" || o.counts["a"] != 1 {
		t.Fatal("independent descriptor or lease overwritten")
	}
	if _, err := o.acquire([]string{"b"}); err == nil {
		t.Fatal("admitted across independent change")
	}
	f.state = owned // independent owner restores its own descriptor
	f.readFailure = true
	if err := close(); err == nil || o.counts["a"] != 1 {
		t.Fatal("failed read consumed release")
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerQueryLeasesConcurrent(t *testing.T) {
	o, f := inertQueryOwner()
	base := f.state
	const n = 24
	var acquired, done sync.WaitGroup
	acquired.Add(n)
	done.Add(n)
	release := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			close, err := o.acquire([]string{fmt.Sprintf("sid-%d", i%3)})
			if err != nil {
				t.Error(err)
			}
			acquired.Done()
			<-release
			if err == nil {
				if err := close(); err != nil {
					t.Error(err)
				}
				if err := close(); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	acquired.Wait()
	if f.state[0] != base[0]+"+sid-0,sid-1,sid-2" {
		t.Errorf("concurrent union=%q", f.state[0])
	}
	close(release)
	done.Wait()
	if f.state != base || f.closed != 1 {
		t.Fatalf("concurrent final state=%v closed=%d", f.state, f.closed)
	}
}
