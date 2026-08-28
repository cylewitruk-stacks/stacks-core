package burnchain

import "sort"

// EpochBoundary is one inclusive epoch activation height.
type EpochBoundary struct {
	Name        string `json:"name"`
	StartHeight int64  `json:"startHeight"`
}

// RewardSchedule defines deterministic reward-cycle and prepare-phase bounds.
type RewardSchedule struct {
	FirstHeight   int64 `json:"firstHeight"`
	CycleLength   int64 `json:"cycleLength"`
	PrepareLength int64 `json:"prepareLength"`
}

// ProtocolSchedule is the finite boundary model used at admission.
type ProtocolSchedule struct {
	Epochs      []EpochBoundary `json:"epochs,omitempty"`
	RewardCycle *RewardSchedule `json:"rewardCycle,omitempty"`
}

// BoundaryAssessment records every known boundary touched by a replacement.
type BoundaryAssessment struct {
	Known                     bool     `json:"known"`
	FromHeight                int64    `json:"fromHeight"`
	ToHeight                  int64    `json:"toHeight"`
	EpochBoundaries           []string `json:"epochBoundaries,omitempty"`
	RewardCycleBoundaries     []int64  `json:"rewardCycleBoundaries,omitempty"`
	PreparePhaseBoundaries    []int64  `json:"preparePhaseBoundaries,omitempty"`
	CrossesEpoch              bool     `json:"crossesEpoch"`
	CrossesRewardCycle        bool     `json:"crossesRewardCycle"`
	CrossesRewardPreparePhase bool     `json:"crossesRewardPreparePhase"`
}

// AssessBoundaries classifies the removed-and-replacement height interval.
// The interval is inclusive because a boundary at either endpoint can change
// how the same burn block is interpreted by Stacks.
func AssessBoundaries(fromHeight, toHeight int64, schedule *ProtocolSchedule) BoundaryAssessment {
	assessment := BoundaryAssessment{FromHeight: fromHeight, ToHeight: toHeight}
	if schedule == nil {
		return assessment
	}
	assessment.Known = true
	for _, epoch := range schedule.Epochs {
		if epoch.StartHeight >= fromHeight && epoch.StartHeight <= toHeight {
			assessment.EpochBoundaries = append(assessment.EpochBoundaries, epoch.Name)
		}
	}
	sort.Strings(assessment.EpochBoundaries)
	assessment.CrossesEpoch = len(assessment.EpochBoundaries) > 0
	if reward := schedule.RewardCycle; reward != nil && reward.CycleLength > 0 {
		firstCycle := int64(0)
		if fromHeight > reward.FirstHeight {
			firstCycle = (fromHeight - reward.FirstHeight) / reward.CycleLength
		}
		for cycle := firstCycle; ; cycle++ {
			start := reward.FirstHeight + cycle*reward.CycleLength
			if start > toHeight {
				break
			}
			if start >= fromHeight {
				assessment.RewardCycleBoundaries = append(assessment.RewardCycleBoundaries, start)
			}
			prepare := start + reward.CycleLength - reward.PrepareLength
			if reward.PrepareLength > 0 && prepare >= fromHeight && prepare <= toHeight {
				assessment.PreparePhaseBoundaries = append(assessment.PreparePhaseBoundaries, prepare)
			}
		}
	}
	assessment.CrossesRewardCycle = len(assessment.RewardCycleBoundaries) > 0
	assessment.CrossesRewardPreparePhase = len(assessment.PreparePhaseBoundaries) > 0
	return assessment
}
