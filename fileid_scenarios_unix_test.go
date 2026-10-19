//go:build darwin || linux

package identity

import "os"

// folderLinkForScenario is a scenario's "link" on POSIX: a symbolic link.
func folderLinkForScenario(link, target string) error { return os.Symlink(target, link) }

// markNetworkVolume makes LocalPath refuse folder as a network volume, the
// target a POSIX share link names.
func markNetworkVolume(folder string) func() { return TreatVolumeAsNetwork(folder) }
