package identity

import "github.com/openabstractions/abstraction-identity/placetest"

// folderLinkForScenario is a scenario's "link" on Windows: a junction.
func folderLinkForScenario(link, target string) error { return placetest.Junction(link, target) }

// markNetworkVolume is unused on Windows, where a share link names a share.
func markNetworkVolume(string) func() { return func() {} }
