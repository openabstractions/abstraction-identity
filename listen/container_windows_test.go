package listen

import (
	"fmt"
	"os"
	"strings"
	"testing"

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
	if s := sd.String(); !strings.Contains(s, container) || !strings.Contains(s, user.User.Sid.String()) {
		t.Fatalf("the pipe's door is %s", s)
	}
}
