package fileid

import "testing"

func TestOrdinalNameExtractionPreservesFileidFallback(t *testing.T) {
	for _, test := range []struct {
		a, b string
		same bool
	}{{"", "", true}, {"Name", "name", true}, {"K", "K", false}, {"x\xff", "x\xff", true}, {"x\xff", "X\xff", false}, {"x\xff", "x\xfe", false}, {"a\x00b", "A\x00B", true}} {
		if same := ordinalEqualIgnoringCase(test.a, test.b); same != test.same {
			t.Fatalf("%q %q: %v", test.a, test.b, same)
		}
	}
}
