package identity

import (
	"path/filepath"
	"testing"
)

// A package full name yields its family, which survives a version change; a
// malformed name yields nothing.
func TestPackageFamilyIgnoresVersionAndArchitecture(t *testing.T) {
	for _, full := range []string{"Claude_2.110.0.0_x64__pzs8sxrjxfjjc", "Claude_2.111.3.0_arm64__pzs8sxrjxfjjc"} {
		if family, ok := PackageFamily(full); !ok || family != "Claude_pzs8sxrjxfjjc" {
			t.Fatalf("%s: %q %v", full, family, ok)
		}
	}
	for _, bad := range []string{"", "Claude", "Claude_pzs8sxrjxfjjc", "Cl_1_x64__pzs8sxrjxfjjc", "Claude_1_x64__PZS8SXRJXFJJC"} {
		if family, ok := PackageFamily(bad); ok {
			t.Fatalf("%q read as family %q", bad, family)
		}
	}
}

// A signed package names the subject by family when the image lies inside the
// package's installed folder. An image elsewhere, run with the package's
// identity, keeps its path, as does a caller without a package. The path must
// meet the path proof.
func TestSubjectProgramPrefersASignedPackageFamily(t *testing.T) {
	installed := t.TempDir()
	image := filepath.Join(installed, "app", "app.exe")
	saved := packageInstallPath
	defer func() { packageInstallPath = saved }()
	packageInstallPath = func(full string) (string, error) {
		if full != "Claude_2.110.0.0_x64__pzs8sxrjxfjjc" {
			t.Fatalf("install path asked for %q", full)
		}
		return installed, nil
	}
	peer := &Peer{
		Path:    attr("path", image+string(filepath.Separator), ProofBound, "fixture"),
		Package: attr("package", "Claude_2.110.0.0_x64__pzs8sxrjxfjjc", ProofSigned, "fixture"),
	}
	got, err := SubjectProgram(peer, ProofBound)
	if err != nil || got != "msix:Claude_pzs8sxrjxfjjc" || !ValidSubjectProgram(got) {
		t.Fatalf("subject %q %v", got, err)
	}
	elsewhere := filepath.Join(t.TempDir(), "tool.exe")
	peer.Path = attr("path", elsewhere, ProofBound, "fixture")
	if got, err := SubjectProgram(peer, ProofBound); err != nil || got != elsewhere {
		t.Fatalf("an image outside the package folder named %q %v", got, err)
	}
	peer.Path = attr("path", installed+"-sibling"+string(filepath.Separator)+"app.exe", ProofBound, "fixture")
	if got, _ := SubjectProgram(peer, ProofBound); got == "msix:Claude_pzs8sxrjxfjjc" {
		t.Fatal("a sibling folder sharing the package folder's prefix named the package")
	}
	peer.Path = attr("path", image, ProofBound, "fixture")
	peer.Package = unknown[string]("package", "an ordinary executable")
	if got, err := SubjectProgram(peer, ProofBound); err != nil || got != image {
		t.Fatalf("unpackaged subject %q %v", got, err)
	}
	if _, err := SubjectProgram(peer, ProofSigned); err == nil {
		t.Fatal("a path below the required proof named a subject")
	}
	for _, bad := range []string{"", "relative.exe", "msix:", "msix:Claude", "msix:../x_pzs8sxrjxfjjc", image + "\n"} {
		if ValidSubjectProgram(bad) {
			t.Fatalf("%q validated", bad)
		}
	}
}
