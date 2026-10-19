package listen

import "testing"

func TestSameEndpointNameUsesNativeNamesWithoutPathNormalization(t *testing.T) {
	for _, test := range []struct {
		a, b string
		same bool
	}{
		{`\\.\pipe\OA-name`, `\\.\PIPE\oa-NAME`, true},
		{`\\.\pipe\K`, `\\.\pipe\K`, false},
		{`\\.\pipe\a\..\b`, `\\.\pipe\b`, false},
		{`\\.\pipe\a/b`, `\\.\pipe\a\b`, false},
	} {
		same, err := SameEndpointName(test.a, test.b)
		if err != nil || same != test.same {
			t.Fatalf("%q %q: %v %v", test.a, test.b, same, err)
		}
	}
	for _, name := range []string{"", "bad\x00name", "bad\xffname"} {
		if same, err := SameEndpointName(name, name); same || err == nil {
			t.Fatal("invalid/uncertain name admitted", same, err)
		}
	}
}
