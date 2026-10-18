package identity

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// [ID-S1] Self names the calling process's own principal: on Windows its
// account SID and a known integrity level, elsewhere its effective uid.
func TestSelfIsTheCurrentProcessPrincipal(t *testing.T) {
	user, err := Self()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if user.Kind != "windows" || !strings.HasPrefix(user.SID, "S-1-") || user.IntegrityRID == 0 || user.Integrity == "unknown" {
			t.Fatalf("self %+v", user)
		}
		return
	}
	if user.Kind != "posix" || user.UID != os.Geteuid() || user.GID != os.Getegid() {
		t.Fatalf("self %+v", user)
	}
}
