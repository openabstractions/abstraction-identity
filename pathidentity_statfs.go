//go:build darwin || linux

package identity

import "github.com/openabstractions/abstraction-identity/fileid"

// TreatVolumeAsNetwork is fileid.TreatVolumeAsNetwork.
func TreatVolumeAsNetwork(folder string) (restore func()) { return fileid.TreatVolumeAsNetwork(folder) }
