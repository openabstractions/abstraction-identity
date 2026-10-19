//go:build windows

package identity

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// The two targets are this process and its primary token. The private seam
// permits deterministic transition failures without changing a process ACL.
type serverQueryTargets interface {
	read(int) (string, error)
	compose(int, string, []string) (string, error)
	write(int, string) error
	close() error
}

type serverQueryTransition struct{ before, after [2]string }

type serverQueryLeases struct {
	sync.Mutex
	open    func() (serverQueryTargets, error)
	targets serverQueryTargets
	base    [2]string
	applied [2]string
	counts  map[string]int
	pending *serverQueryTransition
}

func (o *serverQueryLeases) cleanup() error {
	if o.targets == nil {
		return nil
	}
	if err := o.targets.close(); err != nil {
		return err
	}
	o.targets = nil
	o.base, o.applied = [2]string{}, [2]string{}
	return nil
}

// rollback also receives a write that returned an error after changing its
// target. Only the transition's two known descriptors may be overwritten.
// Failed reads, writes or independent edits retain the pending transition and
// handles; the next operation retries recovery before admitting another lease.
func (o *serverQueryLeases) rollback() error {
	if o.pending == nil {
		return nil
	}
	var result error
	for i := 1; i >= 0; i-- {
		current, err := o.targets.read(i)
		if err == nil && current != o.pending.before[i] {
			if current != o.pending.after[i] {
				err = errors.New("identity: server query ACL changed before restoration")
			} else {
				err = o.targets.write(i, o.pending.before[i])
				if err == nil {
					current, err = o.targets.read(i)
					if err == nil && current != o.pending.before[i] {
						err = errors.New("identity: server query ACL restoration readback differs")
					}
				}
			}
		}
		result = errors.Join(result, err)
	}
	if result == nil {
		o.applied = o.pending.before
		o.pending = nil
	}
	return result
}

func (o *serverQueryLeases) transition(counts map[string]int) error {
	if err := o.rollback(); err != nil {
		return err
	}
	var names []string
	for sid, count := range counts {
		if count > 0 {
			names = append(names, sid)
		}
	}
	slices.Sort(names)
	next := o.base
	for i := range next {
		var err error
		if len(names) != 0 {
			next[i], err = o.targets.compose(i, o.base[i], names)
		}
		if err != nil {
			return err
		}
		current, err := o.targets.read(i)
		if err != nil {
			return err
		}
		if current != o.applied[i] {
			return errors.New("identity: server query ACL changed before restoration")
		}
	}
	o.pending = &serverQueryTransition{before: o.applied, after: next}
	for i := range next {
		if next[i] == o.applied[i] {
			continue
		}
		// Check again immediately before each write, including after a native
		// call on the other target. Independent descriptor edits are retained.
		current, err := o.targets.read(i)
		if err == nil && current != o.applied[i] {
			err = errors.New("identity: server query ACL changed before restoration")
		}
		if err == nil {
			err = o.targets.write(i, next[i])
		}
		if err == nil {
			current, err = o.targets.read(i)
			if err == nil && current != next[i] {
				err = errors.New("identity: server query ACL apply readback differs")
			}
		}
		if err != nil {
			return errors.Join(err, o.rollback())
		}
	}
	o.applied, o.pending = next, nil
	return nil
}

func (o *serverQueryLeases) acquire(names []string) (func() error, error) {
	o.Lock()
	defer o.Unlock()
	if err := o.rollback(); err != nil {
		return nil, err
	}
	if len(o.counts) == 0 {
		if err := o.cleanup(); err != nil {
			return nil, err
		}
	}
	if o.targets == nil {
		var err error
		o.targets, err = o.open()
		if err != nil {
			return nil, err
		}
		for i := range o.base {
			o.base[i], err = o.targets.read(i)
			if err != nil {
				return nil, errors.Join(err, o.cleanup())
			}
		}
		o.applied = o.base
	}
	next := make(map[string]int, len(o.counts)+len(names))
	for sid, count := range o.counts {
		next[sid] = count
	}
	for _, sid := range names {
		next[sid]++
	}
	if err := o.transition(next); err != nil {
		if len(o.counts) == 0 && o.pending == nil {
			err = errors.Join(err, o.cleanup())
		}
		return nil, err
	}
	o.counts = next
	owned := slices.Clone(names)
	released := false
	return func() error {
		o.Lock()
		defer o.Unlock()
		if released {
			if len(o.counts) == 0 && o.pending == nil {
				return o.cleanup()
			}
			return nil
		}
		next := make(map[string]int, len(o.counts))
		for sid, count := range o.counts {
			next[sid] = count
		}
		for _, sid := range owned {
			if next[sid] <= 0 {
				return fmt.Errorf("identity: missing server query lease for %s", sid)
			}
			next[sid]--
			if next[sid] == 0 {
				delete(next, sid)
			}
		}
		if err := o.transition(next); err != nil {
			return err
		}
		o.counts, released = next, true
		if len(next) == 0 {
			return o.cleanup()
		}
		return nil
	}, nil
}
