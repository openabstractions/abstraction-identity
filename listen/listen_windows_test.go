package listen

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestAPipeNameBelongsToTheFirstListener(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	first, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Listen(name)
	if err == nil {
		second.Close()
		t.Fatal("a second listener took a name that was already served")
	}
	if !errors.Is(err, ErrTaken) {
		t.Fatalf("the second listener was refused for the wrong reason: %v", err)
	}
	first.Close()
	again, err := Listen(name)
	if err != nil {
		t.Fatalf("the name was still taken after its listener closed: %v", err)
	}
	again.Close()
}
