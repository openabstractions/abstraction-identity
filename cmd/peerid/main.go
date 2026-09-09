// Command peerid shows what this machine can prove about the program on the
// other end of a local connection, and then attacks it.
//
//	go run ./identity/cmd/peerid
//
// Round one is an honest caller. Round two is the same caller impersonating a
// system program, using this platform's own version of the trick. Both answers
// are printed side by side: the one a lookup gives, and the one a binding
// taken at accept gives. Nothing is simulated - every line is a real
// connection between two real processes on this machine.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	identity "github.com/openabstractions/abstraction-identity"
)

// The policy the pretend service enforces: name the calling program, at the
// strongest this machine says it can. It is taken from Ceiling rather than
// written down, because a policy above the ceiling is refused for everybody and
// proves nothing about the attack.
var policy = func() identity.Need {
	l := identity.Ceiling()
	return identity.Need{User: l.Best.User, Path: l.Best.Path}
}()

type answer struct {
	peer *identity.Peer
	err  error
}

type round struct {
	title     string
	narration []string
	verdict   string
	captured  answer
	lookup    answer
	rebound   answer
}

func main() {
	if mode := os.Getenv(roleEnv); mode != "" {
		os.Exit(runRole(mode))
	}
	flag.Parse()

	l := identity.Ceiling()
	fmt.Printf("peerid  %s/%s\n\n", l.Platform, l.Transport)
	fmt.Println("what this machine can prove")
	fmt.Printf("  user %-7s process %-7s path %-7s package %-7s code %s\n",
		l.Best.User, l.Best.Process, l.Best.Path, l.Best.Package, l.Best.Code)
	fmt.Printf("  can a peer be bound to the connection?  %s\n", yesno(l.Bindable))
	fmt.Printf("%s\n", wrap("    ", l.Binding))
	if l.Stronger != "" {
		fmt.Println("  what would prove more")
		fmt.Printf("%s\n", wrap("    ", l.Stronger))
	}
	fmt.Println()

	failed := 0
	last := ""
	for _, r := range []func() (*round, error){honestRound, attackRound} {
		got, err := r()
		if err != nil {
			fmt.Printf("  the round could not be run: %v\n\n", err)
			failed++
			continue
		}
		printRound(got)
		last = got.verdict
	}
	if failed > 0 {
		os.Exit(1)
	}
	fmt.Printf("verdict  %s/%s: %s\n", l.Platform, l.Transport, last)
}

func printRound(r *round) {
	fmt.Printf("%s\n", r.title)
	for _, n := range r.narration {
		fmt.Printf("  %s\n", n)
	}
	fmt.Println()
	fmt.Println("  bound at accept, before the service read anything")
	report(r.captured, "    ")
	fmt.Println()
	fmt.Println("  asked again now, by lookup - what OfHandle answers")
	report(r.lookup, "    ")
	fmt.Println()
	fmt.Println("  asked again now, through the binding - what Bind answers")
	report(r.rebound, "    ")
	fmt.Println()
}

func report(a answer, pad string) {
	if a.err != nil {
		fmt.Printf("%sREFUSED  %v\n", pad, a.err)
		fmt.Printf("%spolicy %s  ->  REFUSED\n", pad, describe(policy))
		return
	}
	fmt.Printf("%s%s\n", pad, a.peer.User)
	fmt.Printf("%s%s\n", pad, a.peer.Path)
	if code, p := a.peer.Code.Get(); p > identity.ProofNone {
		fmt.Printf("%scode %v [%s]\n", pad, code, p)
	}
	switch err := a.peer.Check(policy); {
	case err == nil:
		fmt.Printf("%spolicy %s  ->  GRANTED\n", pad, describe(policy))
	default:
		fmt.Printf("%spolicy %s  ->  REFUSED  %v\n", pad, describe(policy), oneLine(err))
	}
}

func describe(n identity.Need) string {
	return fmt.Sprintf("{user>=%s path>=%s}", n.User, n.Path)
}

func yesno(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

// oneLine keeps a refusal readable. The parenthesised half of a ProofError is
// the whole reason a platform stops where it does, which belongs in the ceiling
// printed above and not repeated under every attribute.
func oneLine(err error) string {
	s := strings.Join(strings.Split(err.Error(), "\n"), "; ")
	if i := strings.Index(s, " ("); i > 0 {
		s = s[:i]
	}
	return s
}

func wrap(pad, s string) string {
	var out []string
	line := pad
	for _, w := range strings.Fields(s) {
		if len(line)+len(w) > 96 && len(line) > len(pad) {
			out = append(out, line)
			line = pad
		}
		line += w + " "
	}
	return strings.Join(append(out, strings.TrimRight(line, " ")), "\n")
}
