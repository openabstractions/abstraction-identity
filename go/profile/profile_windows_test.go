package profile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A create that lands in root reads real; one redirected into a package's
// LocalCache reads virtualized with that family; neither copy survives.
func TestProfileProbeFindsThePackageCopy(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Packages", "Other_abc", "LocalCache", "Local"), 0o700); err != nil {
		t.Fatal(err)
	}
	real := func(path string) error { return os.WriteFile(path, nil, 0o600) }
	view, err := probeProfile(root, real)
	if err != nil || view.Virtualized || view.String() != "real" {
		t.Fatalf("real create: %+v %v", view, err)
	}
	redirected := func(path string) error {
		copy := filepath.Join(root, "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Local", filepath.Base(path))
		if err := os.MkdirAll(filepath.Dir(copy), 0o700); err != nil {
			return err
		}
		return os.WriteFile(copy, nil, 0o600)
	}
	view, err = probeProfile(root, redirected)
	if err != nil || !view.Virtualized || view.Family != "Claude_pzs8sxrjxfjjc" || view.String() != "virtualized(Claude_pzs8sxrjxfjjc)" {
		t.Fatalf("redirected create: %+v %v", view, err)
	}
	left, _ := filepath.Glob(filepath.Join(root, "Packages", "*", "LocalCache", "Local", ".oa-profile-*"))
	direct, _ := filepath.Glob(filepath.Join(root, ".oa-profile-*"))
	if len(left)+len(direct) != 0 {
		t.Fatalf("probe files left: %v %v", left, direct)
	}
}

// A create that writes the file and then fails (as OpenFile succeeding and
// Close failing would) must not leak the file it already created, in root or
// in a package's redirected copy.
func TestProfileProbeRemovesAfterCreateError(t *testing.T) {
	root := t.TempDir()
	failAfterRealWrite := func(path string) error {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return err
		}
		return errors.New("close failed")
	}
	if _, err := probeProfile(root, failAfterRealWrite); err == nil {
		t.Fatal("expected the create error to propagate")
	}
	if direct, _ := filepath.Glob(filepath.Join(root, ".oa-profile-*")); len(direct) != 0 {
		t.Fatalf("probe file left after a real create error: %v", direct)
	}

	failAfterRedirectedWrite := func(path string) error {
		copy := filepath.Join(root, "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Local", filepath.Base(path))
		if err := os.MkdirAll(filepath.Dir(copy), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(copy, nil, 0o600); err != nil {
			return err
		}
		return errors.New("close failed")
	}
	if _, err := probeProfile(root, failAfterRedirectedWrite); err == nil {
		t.Fatal("expected the create error to propagate")
	}
	if left, _ := filepath.Glob(filepath.Join(root, "Packages", "*", "LocalCache", "Local", ".oa-profile-*")); len(left) != 0 {
		t.Fatalf("package-copy probe file left after a redirected create error: %v", left)
	}
}

// The live probe answers, and OA_EXPECT_PROFILE, when set, names the answer:
// a Claude-contained shell expects virtualized(Claude_pzs8sxrjxfjjc), a
// WMI-started one expects real.
func TestCurrentAnswers(t *testing.T) {
	view, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("profile view: %s", view)
	if want := os.Getenv("OA_EXPECT_PROFILE"); want != "" && view.String() != want {
		t.Fatalf("profile view %s, want %s", view, want)
	}
}
