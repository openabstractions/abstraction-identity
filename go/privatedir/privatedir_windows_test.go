//go:build windows

package privatedir

import (
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
