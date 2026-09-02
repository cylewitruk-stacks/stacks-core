package burnchain

import (
	"strings"
	"testing"
)

func TestPolicyRoundTrip(t *testing.T) {
	t.Parallel()
	want := Policy{
		Generation: 9, Mode: ModePause, IntervalSeconds: 12, JitterSeconds: 3,
		BurstBlocks: 4, BurstTargetHeight: 250, AddressMode: AddressFixed, FixedAddressIndex: 2,
	}
	got, err := ParsePolicy(strings.NewReader(EncodePolicy(want)), PolicyDefaults{IntervalSeconds: 60, MaxDelaySeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("policy mismatch: got %#v, want %#v", got, want)
	}
}

func TestPolicyRejectsOversizeProjection(t *testing.T) {
	t.Parallel()
	input := "#" + strings.Repeat("x", maxPolicyBytes) + "\n"
	if _, err := ParsePolicy(strings.NewReader(input), PolicyDefaults{IntervalSeconds: 60, MaxDelaySeconds: 3600}); err == nil {
		t.Fatal("oversize policy unexpectedly succeeded")
	}
}

func TestPolicyRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	t.Parallel()
	defaults := PolicyDefaults{IntervalSeconds: 60, MaxDelaySeconds: 3600}
	for name, input := range map[string]string{
		"unknown key":     "GENERATION=1\nTYPO=pause\n",
		"duplicate key":   "MODE=run\nMODE=pause\n",
		"invalid mode":    "MODE=automatic\n",
		"negative delay":  "INTERVAL_SECONDS=-1\n",
		"excessive delay": "JITTER_SECONDS=3601\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParsePolicy(strings.NewReader(input), defaults); err == nil {
				t.Fatalf("ParsePolicy(%q) unexpectedly succeeded", input)
			}
		})
	}
}
