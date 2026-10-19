package identity

import (
	"bytes"
	"strings"
	"testing"
)

// The reversed needles spell the upstream markers: Electron's SENTINEL
// (electron/fuses src/constants.ts), Bun's standalone trailer
// (oven-sh/bun src/StandaloneModuleGraph.zig) and the variable Bun reads.
// Each is assembled here by a substitution, so neither this test nor the
// classifier carries the forward bytes. Two halves would not do: the linker
// may lay two literals side by side.
func TestNeedlesSpellUpstreamMarkers(t *testing.T) {
	for name, c := range map[string]struct{ got, want []byte }{
		"electron sentinel": {electronSentinel, []byte(strings.ReplaceAll("dL7pKGdnNz796Pbb#QWNKmHXBZaB9tsX", "#", "j"))},
		"bun trailer":       {bunTrailer, []byte(strings.ReplaceAll("\n---- B#n! ----\n", "#", "u"))},
		"bun variable":      {bunBeBun, []byte(strings.ReplaceAll("BUN_BE_B#N", "#", "U"))},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: %q, want %q", name, c.got, c.want)
		}
	}
}
