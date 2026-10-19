//go:build !windows

package listen

import "testing"

func TestSameEndpointNameUsesExactUnixBytes(t *testing.T) {
	for _, test := range []struct {
		a, b string
		same bool
	}{{"Name", "Name", true}, {"Name", "name", false}, {"x\xff", "x\xff", true}, {"x\xff", "x\xfe", false}, {"a/../b", "b", false}} {
		same, err := SameEndpointName(test.a, test.b)
		if err != nil || same != test.same {
			t.Fatal(same, err)
		}
	}
	if same, err := SameEndpointName("\x00", "\x00"); same || err == nil {
		t.Fatal(same, err)
	}
}
