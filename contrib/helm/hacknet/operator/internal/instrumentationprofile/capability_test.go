package instrumentationprofile

import "testing"

func TestValidateUsesThePortableFiniteVocabulary(t *testing.T) {
	if !Validate([]string{"M01", "M22"}) {
		t.Fatal("known portable families were rejected")
	}
	for _, values := range [][]string{{"M14"}, {"M23"}, {"M01", "M01"}} {
		if Validate(values) {
			t.Fatalf("invalid capability list was accepted: %v", values)
		}
	}
}
