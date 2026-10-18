package listen

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestPipeDescriptorEntries: a listener's door names this account and each
// AppContainer it admits, keeps its label, and refuses a SID that is not one
// AppContainer's before any pipe exists (ID-K1).
func TestPipeDescriptorEntries(t *testing.T) {
	container := "S-1-15-2-46109015-3609682755-774105003-2280802390-3893791985-4224396588-3737174395"
	got := pipeDescriptor("S-1-5-21-1-2-3-1001", "ME", []string{container})
	want := "D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;0x0012019B;;;" + container + ")S:(ML;;NRNWNX;;;ME)"
	if got != want {
		t.Fatalf("descriptor %s, want %s", got, want)
	}
	if got := pipeDescriptor("S-1-5-21-1-2-3-1001", "ME", nil); got != "D:P(A;;FA;;;S-1-5-21-1-2-3-1001)S:(ML;;NRNWNX;;;ME)" {
		t.Fatalf("no container: %s", got)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\oa-test-k1-%d`, os.Getpid())
	for _, refused := range []string{"S-1-15-2-1", "S-1-15-2-2", "S-1-15-3-1", user.User.Sid.String(), "WD", "nonsense"} {
		l, err := ListenAdmitting(name, refused)
		if err == nil {
			l.Close()
			t.Fatalf("%s was admitted", refused)
		}
	}
	l, err := ListenAdmitting(name, container)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(name), windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPipeDoor(sd, user.User.Sid, container); err != nil {
		t.Fatal(err)
	}
}

func checkPipeDoor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, container string) error {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return fmt.Errorf("pipe DACL must have exactly two entries: %v", err)
	}
	app, err := windows.StringToSid(container)
	if err != nil {
		return err
	}
	seenUser, seenApp := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return fmt.Errorf("pipe entry %d has unexpected type or flags", i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(user) && !seenUser && ace.Mask == 0x001f01ff:
			seenUser = true
		case sid.Equals(app) && !seenApp && ace.Mask == 0x0012019b:
			seenApp = true
		default:
			return fmt.Errorf("pipe entry %d has an unexpected trustee, mask or duplicate", i)
		}
	}
	if !seenUser || !seenApp {
		return fmt.Errorf("pipe DACL is missing an expected trustee")
	}
	return nil
}

func TestPipeDoorTrusteesUseSIDIdentity(t *testing.T) {
	const container = "S-1-15-2-46109015-3609682755-774105003-2280802390-3893791985-4224396588-3737174395"
	user, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl string
		good       bool
	}{
		{"alias", "D:P(A;;FA;;;SY)(A;;0x12019b;;;" + container + ")", true},
		{"wrong_principal", "D:P(A;;FA;;;BA)(A;;0x12019b;;;" + container + ")", false},
		{"wrong_mask", "D:P(A;;FR;;;SY)(A;;0x12019b;;;" + container + ")", false},
		{"extra_grant", "D:P(A;;FA;;;SY)(A;;0x12019b;;;" + container + ")(A;;FR;;;WD)", false},
		{"deny_type", "D:P(D;;FA;;;SY)(A;;0x12019b;;;" + container + ")", false},
		{"duplicate", "D:P(A;;FA;;;SY)(A;;FA;;;SY)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkPipeDoor(sd, user, container); (err == nil) != tc.good {
				t.Fatalf("good=%v: %v", tc.good, err)
			}
		})
	}
}

func TestPipeDoorLocalAdministratorSIDSpelling(t *testing.T) {
	const container = "S-1-15-2-46109015-3609682755-774105003-2280802390-3893791985-4224396588-3737174395"
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name := current.User.Sid.String()
	if !strings.HasPrefix(name, "S-1-5-21-") {
		t.Skip("account does not have a local/domain RID")
	}
	admin, err := windows.StringToSid(name[:strings.LastIndex(name, "-")] + "-500")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(pipeDescriptor(admin.String(), "ME", []string{container}))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPipeDoor(sd, admin, container); err != nil {
		t.Fatal(err)
	}
	if err := checkPipeDoor(sd, current.User.Sid, container); !current.User.Sid.Equals(admin) && err == nil {
		t.Fatal("administrator entry admitted a different account")
	}
}
