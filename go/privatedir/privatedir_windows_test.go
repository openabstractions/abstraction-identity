//go:build windows

package privatedir

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// INF-EL2, INF-MS7 on Windows: a private folder passes only when this
// account owns it and its protected DACL allows this account and SYSTEM
// alone. Another
// owner, an inherited DACL, a third principal, an absent DACL and a deny
// entry beside the two are judged on descriptors, since a test cannot give a
// folder another owner without privilege.
func TestThePrivateFolderDescriptorRule(t *testing.T) {
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	user := token.User.Sid
	me := user.String()
	for name, c := range map[string]struct {
		sddl string
		pass bool
	}{
		"private":                 {"O:" + me + "D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)", true},
		"account alone":           {"O:" + me + "D:P(A;OICI;FA;;;" + me + ")", true},
		"deny beside":             {"O:" + me + "D:P(D;;FA;;;WD)(A;OICI;FA;;;" + me + ")", true},
		"owned by SYSTEM":         {"O:SYD:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)", false},
		"owned by Administrators": {"O:BAD:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)", false},
		"inherits":                {"O:" + me + "D:(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)", false},
		"Administrators allowed":  {"O:" + me + "D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;BA)", false},
		"Everyone reads":          {"O:" + me + "D:P(A;OICI;FA;;;" + me + ")(A;OICI;FR;;;WD)", false},
		"no DACL":                 {"O:" + me + "D:NO_ACCESS_CONTROL", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = checkDescriptor(sd, user)
		if (err == nil) != c.pass {
			t.Fatalf("%s: %v, wanted pass=%v", name, err, c.pass)
		}
	}
}

func TestCheckFileWindowsActualDescriptor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := Ensure(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.json")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err != nil {
		t.Fatalf("safe inherited file: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatalf("fixture must exercise inherited CAS-style DACL: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := windows.SecurityDescriptorFromString("O:SYD:(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if err = checkOwnerDescriptor(foreignOwner, user.User.Sid, false); err == nil {
		t.Fatal("foreign owner accepted")
	}
	unsafeSD, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := unsafeSD.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err = CheckDir(root); err != nil {
		t.Fatalf("parent must remain private: %v", err)
	}
	if err = CheckFile(path); err == nil {
		t.Fatal("foreign read ACE accepted under private parent")
	}
}
