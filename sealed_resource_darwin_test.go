//go:build darwin && cgo

package identity

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

func TestVerifySealedResourceDarwinRefusesAdHoc(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Host.app")
	for _, dir := range []string{"Contents/MacOS", "Contents/Resources"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	program := filepath.Join(root, "Contents/MacOS/host")
	// An owned copy of this test image supplies an executable fixture. Its
	// ad-hoc signature is a refusal control, never publisher evidence.
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(program, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "Contents/Info.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.openabstractions.sealed-resource-test</string><key>CFBundleExecutable</key><string>host</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "Contents/Resources/data"), []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--force", "--sign", "-", root).CombinedOutput(); err != nil {
		t.Fatalf("sign owned fixture: %v: %s", err, out)
	}
	b, err := fileid.Open(ctx, fileid.Self, root, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := fileid.Open(ctx, fileid.Self, program, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	e, c, proof, err := VerifySealedResource(ctx, b, p, "Resources/data", 6)
	if e != nil || c != (Code{}) || proof != ProofUnmet || !errors.Is(err, ErrNotProven) {
		t.Fatalf("ad-hoc result %v %v %v %v", e, c, proof, err)
	}
}
