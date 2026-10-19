package winordinal

import (
	"errors"
	"testing"
)

func TestOrdinalComparisonReportsUnavailableEvidence(t *testing.T) {
	before := compareOrdinal
	t.Cleanup(func() { compareOrdinal = before })
	failure := errors.New("native query failed")
	compareOrdinal = func([]uint16, []uint16) (uintptr, error) { return 0, failure }
	if same, err := EqualIgnoringCase("a", "A"); same || !errors.Is(err, failure) {
		t.Fatal(same, err)
	}
	compareOrdinal = func([]uint16, []uint16) (uintptr, error) { return 0, nil }
	if same, err := EqualIgnoringCase("a", "A"); same || err == nil {
		t.Fatal(same, err)
	}
}
