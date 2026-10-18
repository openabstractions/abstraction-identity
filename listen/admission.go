package listen

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var endpointAdmission = struct {
	sync.RWMutex
	entries map[string][]string
}{entries: make(map[string][]string)}

// ConfigureAdmission installs immutable Windows AppContainer admission for the
// exact endpoints this native server will open. The server calls it before any
// listener constructor and releases it after closing all those listeners.
// Unconfigured endpoints retain their ordinary account-only door. No connection
// or request can change this configuration or gain OA operation authority.
func ConfigureAdmission(endpoints, containers []string) (func(), error) {
	if len(endpoints) == 0 || len(containers) == 0 {
		return nil, errors.New("listen: admission requires endpoints and containers")
	}
	seen := make(map[string]bool)
	for _, sid := range containers {
		parts := strings.Split(sid, "-")
		if len(parts) != 11 || strings.Join(parts[:4], "-") != "S-1-15-2" || seen[sid] {
			return nil, fmt.Errorf("listen: invalid or repeated AppContainer SID %q", sid)
		}
		for _, part := range parts[4:] {
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil || strconv.FormatUint(n, 10) != part {
				return nil, fmt.Errorf("listen: invalid AppContainer SID %q", sid)
			}
		}
		seen[sid] = true
	}
	seen = make(map[string]bool)
	for _, endpoint := range endpoints {
		if endpoint == "" || strings.ContainsAny(endpoint, "\x00\r\n") || seen[endpoint] {
			return nil, errors.New("listen: invalid or repeated admission endpoint")
		}
		seen[endpoint] = true
	}
	endpointAdmission.Lock()
	defer endpointAdmission.Unlock()
	for _, endpoint := range endpoints {
		if _, exists := endpointAdmission.entries[endpoint]; exists {
			return nil, fmt.Errorf("listen: admission already configured for %s", endpoint)
		}
	}
	for _, endpoint := range endpoints {
		endpointAdmission.entries[endpoint] = slices.Clone(containers)
	}
	var once sync.Once
	owned := slices.Clone(endpoints)
	return func() {
		once.Do(func() {
			endpointAdmission.Lock()
			defer endpointAdmission.Unlock()
			for _, endpoint := range owned {
				delete(endpointAdmission.entries, endpoint)
			}
		})
	}, nil
}

func admittedContainers(endpoint string) []string {
	endpointAdmission.RLock()
	defer endpointAdmission.RUnlock()
	return slices.Clone(endpointAdmission.entries[endpoint])
}
