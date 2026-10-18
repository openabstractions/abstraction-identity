//go:build windows

package identity

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// AdmitServerQueries lets named AppContainers establish this process's existing
// native server proof. It grants only process limited-query and token query on
// this process, retains mandatory labels, and restores its own DACL effects.
// The uncontained server supplies validated installation SIDs, never a caller.
func AdmitServerQueries(containers ...string) (func() error, error) {
	if len(containers) == 0 {
		return nil, errors.New("identity: server query admission requires containers")
	}
	sids := make([]*windows.SID, 0, len(containers))
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
		sids = append(sids, sid)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.READ_CONTROL|windows.WRITE_DAC, false, windows.GetCurrentProcessId())
	if err != nil {
		return nil, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.READ_CONTROL|windows.WRITE_DAC, &token); err != nil {
		windows.CloseHandle(process)
		return nil, err
	}
	type effect struct {
		handle  windows.Handle
		before  *windows.SECURITY_DESCRIPTOR
		applied string
	}
	var effects []effect
	var once sync.Once
	var closeErr error
	close := func() error {
		once.Do(func() {
			for i := len(effects) - 1; i >= 0; i-- {
				e := effects[i]
				current, err := windows.GetSecurityInfo(e.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
				if err != nil || current.String() != e.applied {
					closeErr = errors.Join(closeErr, fmt.Errorf("identity: server query ACL changed before restoration: %v", err))
					continue
				}
				acl, _, err := e.before.DACL()
				if err == nil {
					err = windows.SetSecurityInfo(e.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
				}
				closeErr = errors.Join(closeErr, err)
			}
			closeErr = errors.Join(closeErr, token.Close(), windows.CloseHandle(process))
		})
		return closeErr
	}
	for _, target := range []struct {
		handle windows.Handle
		mask   windows.ACCESS_MASK
	}{
		{process, windows.PROCESS_QUERY_LIMITED_INFORMATION}, {windows.Handle(token), windows.TOKEN_QUERY},
	} {
		before, err := windows.GetSecurityInfo(target.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return nil, errors.Join(err, close())
		}
		old, _, err := before.DACL()
		if err != nil || old == nil {
			return nil, errors.Join(errors.New("identity: server query admission requires an existing DACL"), err, close())
		}
		acl, err := windows.ACLFromEntries(serverQueryEntries(sids, target.mask), old)
		if err != nil {
			return nil, errors.Join(err, close())
		}
		if err := windows.SetSecurityInfo(target.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			return nil, errors.Join(err, close())
		}
		// Record the applied descriptor even when its subsequent read fails;
		// restore through the still-open object before returning failure.
		applied, err := windows.GetSecurityInfo(target.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			original, _, originalErr := before.DACL()
			restoreErr := windows.SetSecurityInfo(target.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, original, nil)
			return nil, errors.Join(err, originalErr, restoreErr, close())
		}
		effects = append(effects, effect{target.handle, before, applied.String()})
	}
	return close, nil
}

func serverQueryEntries(sids []*windows.SID, mask windows.ACCESS_MASK) []windows.EXPLICIT_ACCESS {
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: mask, AccessMode: windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(sid)}})
	}
	return entries
}
