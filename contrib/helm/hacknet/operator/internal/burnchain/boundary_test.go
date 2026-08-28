package burnchain

import "testing"

func TestAssessBoundariesClassifiesEpochAndRewardTransitions(t *testing.T) {
	t.Parallel()
	schedule := &ProtocolSchedule{
		Epochs:      []EpochBoundary{{Name: "epoch-3", StartHeight: 225}, {Name: "epoch-2", StartHeight: 203}},
		RewardCycle: &RewardSchedule{FirstHeight: 0, CycleLength: 20, PrepareLength: 5},
	}
	assessment := AssessBoundaries(199, 226, schedule)
	if !assessment.Known || !assessment.CrossesEpoch || !assessment.CrossesRewardCycle || !assessment.CrossesRewardPreparePhase {
		t.Fatalf("unexpected assessment: %#v", assessment)
	}
	if len(assessment.EpochBoundaries) != 2 || assessment.EpochBoundaries[0] != "epoch-2" {
		t.Fatalf("epoch boundaries were not deterministic: %#v", assessment.EpochBoundaries)
	}
}

func TestAssessBoundariesPreservesUnknownSchedule(t *testing.T) {
	t.Parallel()
	assessment := AssessBoundaries(100, 110, nil)
	if assessment.Known || assessment.CrossesEpoch || assessment.CrossesRewardCycle {
		t.Fatalf("unknown schedule was fabricated: %#v", assessment)
	}
}
