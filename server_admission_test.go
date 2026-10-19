//go:build windows

package identity

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"
)

func TestServerQueryEntriesHaveOnlyExplicitQueryMasks(t *testing.T) {
	sid, err := windows.StringToSid("S-1-15-2-1-2-3-4-5-6-7")
	if err != nil {
		t.Fatal(err)
	}
	for _, mask := range []windows.ACCESS_MASK{windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE, windows.TOKEN_QUERY} {
		entries := serverQueryEntries([]*windows.SID{sid}, mask)
		if len(entries) != 1 || entries[0].AccessPermissions != mask || entries[0].Inheritance != 0 || entries[0].AccessMode != windows.GRANT_ACCESS {
			t.Fatalf("query ACE = %+v", entries)
		}
	}
}

func TestServerQueryAdmissionGrantsActualProcessWaitAndRestores(t *testing.T) {
	if os.Getenv("OA_IDENTITY_SERVER_QUERY_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestServerQueryAdmissionGrantsActualProcessWaitAndRestores$", "-test.v")
		child.Env = append(os.Environ(), "OA_IDENTITY_SERVER_QUERY_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("disposable admission child: %v\n%s", err, output)
		} else {
			t.Logf("disposable admission child:\n%s", output)
		}
		return
	}
	// Inspect the actual owning admission call on this disposable test process.
	// This SID creates no AppContainer profile and is never an owner runtime SID.
	const container = "S-1-15-2-977-1-2-3-4-5-6"
	sid, err := windows.StringToSid(container)
	if err != nil {
		t.Fatal(err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.READ_CONTROL, false, windows.GetCurrentProcessId())
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.READ_CONTROL, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	targets := []struct {
		handle windows.Handle
		mask   windows.ACCESS_MASK
	}{
		{process, windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE},
		{windows.Handle(token), windows.TOKEN_QUERY},
	}
	read := func(h windows.Handle) *windows.SECURITY_DESCRIPTOR {
		t.Helper()
		sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	before := []string{read(process).String(), read(windows.Handle(token)).String()}
	restore, err := AdmitServerQueries(container)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	for i, target := range targets {
		acl, _, err := read(target.handle).DACL()
		if err != nil || acl == nil {
			t.Fatalf("target%d DACL: %v", i, err)
		}
		found := 0
		for n := uint32(0); n < uint32(acl.AceCount); n++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err = windows.GetAce(acl, n, &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				continue
			}
			if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
				found++
				if ace.Mask != target.mask || ace.Header.AceFlags != 0 {
					t.Fatalf("target%d admitted mask=%x flags=%x want exact%x", i, ace.Mask, ace.Header.AceFlags, target.mask)
				}
			}
		}
		if found != 1 {
			t.Fatalf("target%d exact named admission count=%d", i, found)
		}
	}
	if err = restore(); err != nil {
		t.Fatal(err)
	}
	if err = restore(); err != nil {
		t.Fatal(err)
	}
	for i, target := range targets {
		if read(target.handle).String() != before[i] {
			t.Fatalf("target%d DACL not restored", i)
		}
	}
	const other = "S-1-15-2-978-1-2-3-4-5-6"
	for _, same := range []bool{false, true} {
		for _, first := range []int{0, 1} {
			names := []string{container, other}
			if same {
				names[1] = container
			}
			var release [2]func() error
			for i, name := range names {
				release[i], err = AdmitServerQueries(name)
				if err != nil {
					t.Fatal(err)
				}
				defer release[i]()
			}
			if err = release[first](); err != nil {
				t.Fatal(err)
			}
			for _, target := range targets {
				current := read(target.handle).String()
				if !strings.Contains(current, names[1-first]) {
					t.Fatalf("active SID lost: %s", current)
				}
				if !same && strings.Contains(current, names[first]) {
					t.Fatalf("closed SID retained: %s", current)
				}
			}
			if err = release[1-first](); err != nil {
				t.Fatal(err)
			}
			for i, target := range targets {
				if read(target.handle).String() != before[i] {
					t.Fatalf("overlap target%d baseline differs", i)
				}
			}
		}
	}
}
