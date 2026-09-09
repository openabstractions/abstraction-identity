package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestAttrWillNotHandOutAValueBelowTheRequiredProof(t *testing.T) {
	a := attr("path", `C:\a.exe`, ProofPID, "read from a pid without checking for reuse")

	if v, err := a.AtLeast(ProofPID); err != nil || v != `C:\a.exe` {
		t.Errorf("AtLeast(ProofPID) = %q, %v; want the value", v, err)
	}
	v, err := a.AtLeast(ProofBound)
	if err == nil {
		t.Fatal("AtLeast(ProofBound) returned a value proven only at ProofPID")
	}
	if v != "" {
		t.Errorf("AtLeast returned %q alongside its error; it must return the zero value", v)
	}
	if !errors.Is(err, ErrNotProven) {
		t.Errorf("err = %v, want ErrNotProven", err)
	}
	if !strings.Contains(err.Error(), "checking for reuse") {
		t.Errorf("err = %q, want it to carry the reason", err)
	}
}

func TestUnknownAttrIsNeverHandedOut(t *testing.T) {
	a := unknown[string]("code", "no signature")
	if a.Known() {
		t.Error("an unknown attribute reports itself as known")
	}
	// ProofNone must not satisfy a request for ProofNone either: there is no
	// value behind it.
	if _, err := a.AtLeast(ProofNone); err == nil {
		t.Error("AtLeast(ProofNone) handed out a value that does not exist")
	}
	if !strings.Contains(a.String(), "unknown") {
		t.Errorf("String() = %q, want it to say unknown", a)
	}
}

func TestAttrStringAlwaysCarriesTheProof(t *testing.T) {
	s := attr("user", "alice", ProofKernel, "").String()
	if !strings.Contains(s, "kernel") {
		t.Errorf("String() = %q; a log line must not be able to look stronger than it is", s)
	}
}

func TestCheckReportsEveryShortfallAtOnce(t *testing.T) {
	p := &Peer{
		User:    attr("user", User{Kind: "windows", SID: "S-1-5-21-1"}, ProofKernel, ""),
		Process: attr("process", Process{PID: 42}, ProofKernel, ""),
		Path:    attr("path", `C:\a.exe`, ProofPID, "racy"),
		Package: unknown[string]("package", "not packaged"),
		Code:    unknown[Code]("code", "no signature"),
	}
	err := p.Check(Need{User: ProofKernel, Path: ProofBound, Package: ProofSigned, Code: ProofSigned})
	if err == nil {
		t.Fatal("Check passed a policy the peer does not meet")
	}
	for _, want := range []string{"path", "package", "code"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Check error %q does not mention %q; a caller would fix one requirement at a time", err, want)
		}
	}
	if strings.Contains(err.Error(), "user") {
		t.Errorf("Check error %q complains about an attribute that was satisfied", err)
	}
	if err := p.Check(Need{User: ProofKernel, Process: ProofKernel}); err != nil {
		t.Errorf("Check refused a policy the peer meets: %v", err)
	}
	if err := p.Check(Need{}); err != nil {
		t.Errorf("the zero Need should require nothing, got %v", err)
	}
}

func TestProofOrderIsTheDocumentedOne(t *testing.T) {
	order := []Proof{ProofNone, ProofClaimed, ProofPID, ProofBound, ProofKernel, ProofSigned}
	for i := 1; i < len(order); i++ {
		if !(order[i-1] < order[i]) {
			t.Fatalf("%s is not weaker than %s", order[i-1], order[i])
		}
	}
	// ProofClaimed sits below everything the operating system says, which is
	// the whole point of it existing.
	if ProofClaimed >= ProofPID {
		t.Error("a claim by the peer ranks at or above something the OS said")
	}
	if got := Proof(99).String(); !strings.Contains(got, "99") {
		t.Errorf("unknown proof rendered as %q", got)
	}
}

func TestCeilingExplainsItself(t *testing.T) {
	l := Ceiling()
	if l.Platform == "" {
		t.Error("the ceiling does not say which platform it describes")
	}
	for _, k := range []string{"user", "process", "path", "package", "code"} {
		if l.Why[k] == "" {
			t.Errorf("no reason given for the ceiling on %q", k)
		}
	}
	if err := CanEver(Need{}); err != nil {
		t.Errorf("CanEver(zero Need) = %v, want nil: requiring nothing is always satisfiable", err)
	}
}

// TestUnsupportedPlatformsRefuseRatherThanGuess is the seam, asserted. On a
// platform with no implementation, every proof ceiling is ProofNone, so any
// policy at all is rejected at startup instead of being silently downgraded at
// connect time.
func TestUnsupportedPlatformsRefuseRatherThanGuess(t *testing.T) {
	l := Ceiling()
	if l.Platform != "unsupported" {
		t.Skipf("%s is implemented; the seam is asserted by the builds that are not", l.Platform)
	}
	if l.Best != (Need{}) {
		t.Errorf("an unimplemented platform advertises a ceiling of %v; it must promise nothing", l.Best)
	}
	if err := CanEver(Need{User: ProofPID}); err == nil {
		t.Error("an unimplemented platform accepted a policy")
	}
	if _, err := OfHandle(Handle(0), nil); !errors.Is(err, ErrUnimplemented) {
		t.Errorf("OfHandle = %v, want ErrUnimplemented rather than a weak answer", err)
	}
}

// TestOfConnRefusesAConnItCannotIdentify: a net.Conn with no reachable handle
// must be refused, not answered from something else.
func TestOfConnRefusesAConnItCannotIdentify(t *testing.T) {
	if _, err := OfConn(opaqueConn{}, nil); !errors.Is(err, ErrUnsupportedConn) {
		t.Errorf("OfConn = %v, want ErrUnsupportedConn", err)
	}
}
