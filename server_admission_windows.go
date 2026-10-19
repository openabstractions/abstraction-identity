//go:build windows

package identity

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

var serverQueries = serverQueryLeases{open: openServerQueryTargets}

// AdmitServerQueries lets named AppContainers establish this process's existing
// native server proof. It grants process limited-query and synchronize (the
// held-process liveness wait), and token query on
// this process, retains mandatory labels, and restores its own DACL effects.
// The uncontained server supplies validated installation SIDs, never a caller.
// Overlapping admissions retain each SID until its final lease is released.
// A failed release retains its recovery state and may be retried.
func AdmitServerQueries(containers ...string) (func() error, error) {
	if len(containers) == 0 {
		return nil, errors.New("identity: server query admission requires containers")
	}
	names := make([]string, 0, len(containers))
	seen := make(map[string]bool)
	for _, value := range containers {
		sid, err := windows.StringToSid(value)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(sid.String(), "-")
		if len(parts) != 11 || strings.Join(parts[:4], "-") != "S-1-15-2" || value != sid.String() || seen[value] {
			return nil, fmt.Errorf("identity: not one unique AppContainer SID: %s", value)
		}
		seen[value] = true
		names = append(names, value)
	}
	return serverQueries.acquire(names)
}

type nativeServerQueryTargets struct{ handles [2]windows.Handle }

func openServerQueryTargets() (serverQueryTargets, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.READ_CONTROL|windows.WRITE_DAC, false, windows.GetCurrentProcessId())
	if err != nil {
		return nil, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.READ_CONTROL|windows.WRITE_DAC, &token); err != nil {
		windows.CloseHandle(process)
		return nil, err
	}
	return &nativeServerQueryTargets{handles: [2]windows.Handle{process, windows.Handle(token)}}, nil
}

func (t *nativeServerQueryTargets) read(i int) (string, error) {
	sd, err := windows.GetSecurityInfo(t.handles[i], windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return "", errors.Join(errors.New("identity: server query admission requires an existing DACL"), err)
	}
	return sd.String(), nil
}

func (t *nativeServerQueryTargets) compose(i int, baseline string, names []string) (string, error) {
	sd, err := windows.SecurityDescriptorFromString(baseline)
	if err != nil {
		return "", err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	sids := make([]*windows.SID, 0, len(names))
	for _, name := range names {
		sid, err := windows.StringToSid(name)
		if err != nil {
			return "", err
		}
		sids = append(sids, sid)
	}
	mask := windows.ACCESS_MASK(windows.TOKEN_QUERY)
	if i == 0 {
		mask = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE
	}
	acl, err := windows.ACLFromEntries(serverQueryEntries(sids, mask), old)
	if err != nil {
		return "", err
	}
	absolute, err := sd.ToAbsolute()
	if err != nil {
		return "", err
	}
	if err = absolute.SetDACL(acl, true, false); err != nil {
		return "", err
	}
	return absolute.String(), nil
}

func (t *nativeServerQueryTargets) write(i int, descriptor string) error {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(t.handles[i], windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func (t *nativeServerQueryTargets) close() error {
	var result error
	for i := len(t.handles) - 1; i >= 0; i-- {
		if t.handles[i] != 0 {
			err := windows.CloseHandle(t.handles[i])
			result = errors.Join(result, err)
			if err == nil {
				t.handles[i] = 0
			}
		}
	}
	return result
}

func serverQueryEntries(sids []*windows.SID, mask windows.ACCESS_MASK) []windows.EXPLICIT_ACCESS {
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: mask, AccessMode: windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(sid)}})
	}
	return entries
}
