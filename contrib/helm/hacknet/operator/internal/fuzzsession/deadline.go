package fuzzsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
)

// now returns the injected or system UTC clock.
func (engine *Engine) now() time.Time {
	if engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}

// sessionContext preserves the original session wall-time budget on resume.
func (engine *Engine) sessionContext(
	parent context.Context,
	records []fuzzcorpus.JournalRecord,
	maximum time.Duration,
) (context.Context, context.CancelFunc, error) {
	return engine.contextFromJournal(parent, records, "SessionPlanned", 0, maximum)
}

// reductionContext preserves the original reduction wall-time budget on resume.
func (engine *Engine) reductionContext(
	parent context.Context,
	records []fuzzcorpus.JournalRecord,
	ordinal int32,
	maximum time.Duration,
) (context.Context, context.CancelFunc, error) {
	return engine.contextFromJournal(parent, records, "ReductionStarted", ordinal, maximum)
}

// contextFromJournal derives remaining time from one immutable start record.
func (engine *Engine) contextFromJournal(
	parent context.Context,
	records []fuzzcorpus.JournalRecord,
	kind string,
	ordinal int32,
	maximum time.Duration,
) (context.Context, context.CancelFunc, error) {
	if maximum <= 0 {
		return nil, nil, errors.New("bounded operation duration must be positive")
	}
	var startedAt time.Time
	for _, record := range records {
		if record.Kind != kind || (ordinal != 0 && record.TrialOrdinal != ordinal) {
			continue
		}
		if !startedAt.IsZero() {
			return nil, nil, fmt.Errorf("journal contains duplicate %s records", kind)
		}
		startedAt = record.OccurredAt
	}
	if startedAt.IsZero() {
		return nil, nil, fmt.Errorf("journal is missing %s", kind)
	}
	remaining := startedAt.Add(maximum).Sub(engine.now())
	if remaining <= 0 {
		return nil, nil, fmt.Errorf("%s wall-time budget is exhausted", kind)
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, nil
}

// hasTrialRecord reports whether one trial transition is already journaled.
func hasTrialRecord(records []fuzzcorpus.JournalRecord, kind string, ordinal int32) bool {
	for _, record := range records {
		if record.Kind == kind && record.TrialOrdinal == ordinal {
			return true
		}
	}
	return false
}
