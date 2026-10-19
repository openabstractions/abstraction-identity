package fileid

import "sync/atomic"

// openObserver, when set, is told every path identity is about to open or
// read by name (observeOpen); tests count opens with it.
var openObserver atomic.Pointer[func(path string)]

// ObserveOpens is for tests, in this module and in its consumers: until stop
// is called, observe is told every path the walk (Open, Resolve) and, on
// Windows, identity's older path functions are about to open or read by
// name, so a test can show that a refused path was never opened. Off
// Windows the older functions decide a refusal by statfs, which opens
// nothing, and report no open. One observer at a time; ok is false while
// another is set.
func ObserveOpens(observe func(path string)) (stop func(), ok bool) {
	if !openObserver.CompareAndSwap(nil, &observe) {
		return func() {}, false
	}
	return func() { openObserver.CompareAndSwap(&observe, nil) }, true
}

func observeOpen(path string) {
	if observe := openObserver.Load(); observe != nil {
		(*observe)(path)
	}
}
