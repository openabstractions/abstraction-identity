package budget

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWithinFollowsTheCaller(t *testing.T) {
	caller, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	step, stop := Within(caller, time.Second, time.Minute)
	defer stop()
	want, _ := caller.Deadline()
	if got, ok := step.Deadline(); !ok || !got.Equal(want) {
		t.Fatalf("step deadline %v, caller %v", got, want)
	}

	step, stop = Within(context.Background(), time.Second, time.Minute)
	defer stop()
	if got, ok := step.Deadline(); !ok || time.Until(got) < 59*time.Second {
		t.Fatalf("no caller deadline: step deadline %v", got)
	}
}

func TestWithinKeepsTheFloorAndTheCallersCancel(t *testing.T) {
	caller, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	step, stop := Within(caller, time.Second, time.Minute)
	defer stop()
	<-caller.Done()
	time.Sleep(20 * time.Millisecond)
	if step.Err() != nil {
		t.Fatalf("step ended with the caller's deadline inside its floor: %v", step.Err())
	}
	if got, ok := step.Deadline(); !ok || time.Until(got) > time.Second {
		t.Fatalf("floor deadline %v", got)
	}

	caller, cancelCaller := context.WithCancel(context.Background())
	short, cancelShort := context.WithTimeout(caller, time.Second)
	defer cancelShort()
	step, stop = Within(short, 5*time.Second, time.Minute)
	defer stop()
	cancelCaller()
	select {
	case <-step.Done():
		if !errors.Is(step.Err(), context.Canceled) {
			t.Fatalf("step error %v", step.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the caller's cancel did not end the step")
	}

	// A caller cancelled before the step starts gives a step that has
	// already ended, with no wait for a goroutine.
	caller, cancelCaller = context.WithCancel(context.Background())
	short, cancelShort = context.WithTimeout(caller, time.Second)
	defer cancelShort()
	cancelCaller()
	step, stop = Within(short, 5*time.Second, time.Minute)
	defer stop()
	if !errors.Is(step.Err(), context.Canceled) {
		t.Fatalf("step of a cancelled caller: %v", step.Err())
	}
}
