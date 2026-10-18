package listen

import "testing"

func TestAdmissionIsExactImmutableAndReversible(t *testing.T) {
	sid := "S-1-15-2-1-2-3-4-5-6-7"
	input := []string{sid}
	release, err := ConfigureAdmission([]string{"fixture-exact"}, input)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	input[0] = "changed"
	if got := admittedContainers("fixture-exact"); len(got) != 1 || got[0] != sid {
		t.Fatalf("admission = %v", got)
	}
	if len(admittedContainers("fixture-exact-other")) != 0 {
		t.Fatal("unrelated endpoint admitted")
	}
	if _, err := ConfigureAdmission([]string{"fixture-exact"}, []string{sid}); err == nil {
		t.Fatal("live configuration replaced")
	}
	release()
	if len(admittedContainers("fixture-exact")) != 0 {
		t.Fatal("admission retained after owner release")
	}
}

func TestAdmissionRefusesGroupAndMalformedSIDsBeforeRegistration(t *testing.T) {
	for _, sid := range []string{"S-1-15-2-1", "S-1-15-2-1-2-3-4-5-6-07", "S-1-15-3-1-2-3-4-5-6-7"} {
		if _, err := ConfigureAdmission([]string{"fixture-refused"}, []string{sid}); err == nil {
			t.Fatalf("accepted %s", sid)
		}
	}
	if len(admittedContainers("fixture-refused")) != 0 {
		t.Fatal("invalid input left a registration")
	}
}
