package listen

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

const packagedPipePrefix = `\\.\pipe\oa-packaged-`

// A caller running with MSIX package identity is bound at ProofSigned. When its
// image is outside the package's installed folder, as this test binary's is, it
// is still named by its path: any process of the account can start a program
// with an installed package's identity. Set OA_PACKAGED_FAMILY and OA_PACKAGED_APP
// to an installed packaged app's family name and application id, for example
// Claude_pzs8sxrjxfjjc and Claude: Invoke-CommandInDesktopPackage then starts
// this test binary inside that package, and nothing is installed. The test also
// logs what Authenticode reports for the bound image.
func TestAPackagedIdentityOutsideItsFolderKeepsItsPath(t *testing.T) {
	family, app := os.Getenv("OA_PACKAGED_FAMILY"), os.Getenv("OA_PACKAGED_APP")
	if family == "" || app == "" {
		t.Skip("set OA_PACKAGED_FAMILY and OA_PACKAGED_APP to run a client inside an installed package")
	}
	name := fmt.Sprintf("%s%d", packagedPipePrefix, os.Getpid())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := fmt.Sprintf("Invoke-CommandInDesktopPackage -PackageFamilyName %s -AppId %s -Command %s -Args %s -PreventBreakaway",
		quote(family), quote(app), quote(os.Args[0]), quote("-test.run=^TestPackagedClientHelper$ -- "+name))
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("Invoke-CommandInDesktopPackage: %v\n%s", err, out)
	}
	accepted := make(chan Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	var conn Conn
	select {
	case conn = <-accepted:
	case <-time.After(30 * time.Second):
		t.Fatal("the packaged client did not connect")
	}
	defer conn.Close()
	binding, err := conn.Bind()
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	peer := binding.Captured()
	full, proof := peer.Package.Get()
	if proof != identity.ProofSigned {
		t.Fatalf("package %q at %s: %s", full, proof, peer.Package.Why())
	}
	if got, ok := identity.PackageFamily(full); !ok || got != family {
		t.Fatalf("package %q has family %q, want %s", full, got, family)
	}
	path, _ := peer.Path.Get()
	program, err := identity.SubjectProgram(peer, Program.Path)
	if err != nil || program != path {
		t.Fatalf("subject program %q %v, want the image path %s", program, err, path)
	}
	code, codeProof := peer.Code.Get()
	t.Logf("package %s; image %s; Authenticode %s %+v: %s", full, path, codeProof, code, peer.Code.Why())
}

// TestPackagedClientHelper connects to the pipe named after "--" and holds the
// connection while the listener binds it. An ordinary test run passes no pipe,
// and it does nothing.
func TestPackagedClientHelper(t *testing.T) {
	args := flag.Args()
	if len(args) != 1 || !strings.HasPrefix(args[0], packagedPipePrefix) {
		return
	}
	c, err := Dial(args[0])
	if err != nil {
		return
	}
	time.Sleep(2 * time.Second)
	c.Close()
}
