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

func TestPipeNameCanBeReboundWhileOldClientHandleRemainsOpen(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\rebind-held-client-%d-%s`, os.Getpid(), t.Name())
	first, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan Conn, 1)
	go func() {
		server, err := first.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- server
	}()
	client, err := Dial(name)
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		first.Close()
		t.Fatal("the first listener did not accept the client")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Listen(name)
	if err != nil {
		t.Fatalf("the old client's still-open handle holds the name: %v", err)
	}
	again.Close()
}
