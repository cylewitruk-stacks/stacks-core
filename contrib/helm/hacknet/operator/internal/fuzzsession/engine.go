package fuzzsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzreduce"
)

// Artifact is one bounded evidence payload returned by the runtime boundary.
type Artifact struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Data        []byte `json:"data"`
}

// ObservedAttempt is the complete controller and evidence outcome.
type ObservedAttempt struct {
	Policies        []fuzzcorpus.ResourceIdentity `json:"policies"`
	Templates       []fuzzcorpus.ResourceIdentity `json:"templates"`
	EvidencePlane   []fuzzcorpus.ResourceIdentity `json:"evidencePlane"`
	Network         fuzzcorpus.ResourceIdentity   `json:"network"`
	Run             fuzzcorpus.ResourceIdentity   `json:"run"`
	ScheduleDigest  string                        `json:"scheduleDigest"`
	InventoryDigest string                        `json:"inventoryDigest"`
	AttemptID       string                        `json:"attemptId"`
	AttemptKind     string                        `json:"attemptKind"`
	Classification  string                        `json:"classification"`
	StartedAt       time.Time                     `json:"startedAt"`
	FinishedAt      time.Time                     `json:"finishedAt"`
	Result          TrialResult                   `json:"result"`
	Artifacts       []Artifact                    `json:"-"`
}

const retainedAttemptSchema = "stacks-attacknet-fuzz-retained-attempt/v1"

type retainedAttempt struct {
	SchemaVersion string                       `json:"schemaVersion"`
	Attempt       ObservedAttempt              `json:"attempt"`
	Artifacts     []fuzzcorpus.ObjectReference `json:"artifacts"`
}

// Runtime is the narrow side-effect boundary. Implementations may submit only
// ordinary product CRDs plus the session Lease and reservation resources.
type Runtime interface {
	AcquireSession(context.Context, string) (fuzzcorpus.ResourceIdentity, error)
	RenewSession(context.Context, fuzzcorpus.ResourceIdentity, string) (fuzzcorpus.ResourceIdentity, error)
	ReleaseSession(context.Context, fuzzcorpus.ResourceIdentity, string) error
	Capacity(context.Context, fuzzplan.Descriptor) (CapacitySnapshot, error)
	Reserve(context.Context, fuzzplan.Descriptor) ([]fuzzcorpus.ResourceIdentity, error)
	ReleaseReservation(context.Context, []fuzzcorpus.ResourceIdentity) error
	EnsurePolicy(context.Context, *attacknetv1beta1.BurnchainPolicy, *fuzzcorpus.ResourceIdentity, bool) (fuzzcorpus.ResourceIdentity, error)
	EnsureTemplates(context.Context, []attacknetv1beta1.FaultCampaign, []attacknetv1beta1.UpgradeCampaign, []fuzzcorpus.ResourceIdentity) ([]fuzzcorpus.ResourceIdentity, error)
	EnsureNetwork(context.Context, *attacknetv1beta1.StacksNetwork, *fuzzcorpus.ResourceIdentity) (fuzzcorpus.ResourceIdentity, error)
	WaitNetworkReady(context.Context, fuzzcorpus.ResourceIdentity) error
	EnsureEvidencePlane(context.Context, fuzzcorpus.ResourceIdentity, []fuzzcorpus.ResourceIdentity) ([]fuzzcorpus.ResourceIdentity, error)
	ReleaseEvidencePlane(context.Context, []fuzzcorpus.ResourceIdentity) error
	EnsureRun(context.Context, *attacknetv1beta1.AttacknetRun, *fuzzcorpus.ResourceIdentity) (fuzzcorpus.ResourceIdentity, error)
	WaitRunTerminal(context.Context, fuzzcorpus.ResourceIdentity) (ObservedAttempt, error)
	SuspendNetwork(context.Context, fuzzcorpus.ResourceIdentity) error
	Capture(context.Context, ObservedAttempt, int64) (ObservedAttempt, error)
	Teardown(context.Context, ObservedAttempt) error
}

// Engine runs one finite descriptor and records every intent and observation.
type Engine struct {
	Runtime Runtime
	Store   *fuzzcorpus.Store
	Now     func() time.Time
	// LeaseRenewInterval overrides the production heartbeat interval in tests.
	LeaseRenewInterval time.Duration
	// LeaseRenewDeadline overrides the bounded transient-failure window in tests.
	LeaseRenewDeadline time.Duration
	// LeaseRetryInterval overrides the transient renewal retry interval in tests.
	LeaseRetryInterval time.Duration
}

// CorpusExecutionResult is the machine-readable outcome of an explicit
// corpus replay or reduction request.
type CorpusExecutionResult struct {
	SchemaVersion  string `json:"schemaVersion"`
	RequestDigest  string `json:"requestDigest"`
	Fingerprint    string `json:"fingerprint"`
	Classification string `json:"classification"`
	Reduced        bool   `json:"reduced"`
}

type sessionReport struct {
	SchemaVersion           string                `json:"schemaVersion"`
	SessionDigest           string                `json:"sessionDigest"`
	Status                  string                `json:"status"`
	GeneratedFromSequence   int64                 `json:"generatedFromSequence"`
	GeneratedFromDigest     string                `json:"generatedFromDigest"`
	TransitionCounts        map[string]int32      `json:"transitionCounts"`
	CompletedTrials         []int32               `json:"completedTrials,omitempty"`
	CorpusEntries           []sessionEntrySummary `json:"corpusEntries,omitempty"`
	CapacityAdmissionDigest string                `json:"capacityAdmissionDigest,omitempty"`
	ReservationCount        int                   `json:"reservationCount"`
}

type sessionEntrySummary struct {
	Digest         string `json:"digest"`
	Fingerprint    string `json:"fingerprint"`
	Classification string `json:"classification"`
	TrialOrdinal   int32  `json:"trialOrdinal"`
}

// ExecuteCorpus replays one verified entry on a fresh network and optionally
// applies the same bounded removal-only reducer used by unattended sessions.
func (engine *Engine) ExecuteCorpus(
	ctx context.Context,
	descriptor fuzzplan.Descriptor,
	entry fuzzcorpus.Entry,
	attemptID string,
	reduce bool,
) (result CorpusExecutionResult, runErr error) {
	result = CorpusExecutionResult{SchemaVersion: "stacks-attacknet-corpus-execution/v1", Fingerprint: entry.Fingerprint}
	if engine.Runtime == nil || engine.Store == nil || entry.SessionDigest != descriptor.Digest ||
		entry.TrialOrdinal < 1 || entry.TrialOrdinal > int32(len(descriptor.Trials)) || attemptID == "" {
		return result, errors.New("verified corpus entry, descriptor, runtime, store, and attempt identity are required")
	}
	if err := fuzzplan.VerifyDescriptor(descriptor); err != nil {
		return result, err
	}
	if _, err := fuzzplan.FreshName(
		descriptor.SessionID, descriptor.Digest, entry.TrialOrdinal, attemptID,
	); err != nil {
		return result, fmt.Errorf("validate corpus attempt identity: %w", err)
	}
	if reduce && !descriptor.Reduction.Enabled {
		return result, errors.New("corpus entry descriptor does not authorize bounded reduction")
	}
	request := struct {
		SchemaVersion string `json:"schemaVersion"`
		EntryDigest   string `json:"entryDigest"`
		AttemptID     string `json:"attemptId"`
		Reduce        bool   `json:"reduce"`
	}{"stacks-attacknet-corpus-execution-request/v1", entry.Digest, attemptID, reduce}
	requestDigest, err := canonical.Digest(request)
	if err != nil {
		return result, err
	}
	result.RequestDigest = requestDigest
	lock, err := engine.Store.AcquireLock(result.RequestDigest)
	if err != nil {
		return result, err
	}
	defer lock.Release()
	requestReference, err := engine.Store.PutCanonicalObject(
		"corpus-execution-request", "application/json", request,
	)
	if err != nil {
		return result, err
	}
	if requestReference.Digest != result.RequestDigest {
		return result, errors.New("corpus execution request digest changed during retention")
	}
	journal, err := engine.Store.OpenOrCreateJournal(result.RequestDigest)
	if err != nil {
		return result, err
	}
	state, err := recoverState(journal.Records())
	if err != nil {
		return result, err
	}
	if state.SessionComplete {
		if err := engine.verifySessionReport(journal.Records(), result.RequestDigest); err != nil {
			return result, err
		}
		return engine.recoverCorpusExecutionResult(journal.Records(), result.RequestDigest)
	}
	if len(journal.Records()) == 0 {
		descriptorReference, err := engine.Store.PutExactIntegerObject("session-descriptor", "application/json", descriptor)
		if err != nil {
			return result, err
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "SessionPlanned", Phase: "Planned", Artifacts: []fuzzcorpus.ObjectReference{requestReference, descriptorReference}}); err != nil {
			return result, err
		}
	}
	ctx, cancel, err := engine.sessionContext(ctx, journal.Records(), descriptor.MaxDuration.Duration)
	if err != nil {
		return result, err
	}
	defer cancel()
	var lease fuzzcorpus.ResourceIdentity
	var heartbeat *leaseHeartbeat
	if state.LeaseReleaseIntended {
		if state.Lease == nil {
			return result, errors.New("corpus execution cleanup has no lease identity")
		}
		lease = *state.Lease
	} else {
		lease, err = engine.acquireOrResumeLease(ctx, journal, state, result.RequestDigest)
		if err != nil {
			return result, err
		}
		ctx, heartbeat = engine.startLeaseHeartbeat(ctx, lease, result.RequestDigest)
		defer func() {
			heartbeat.Stop()
			if heartbeatErr := heartbeat.TakeError(); heartbeatErr != nil {
				runErr = engine.harnessFailed(journal, "SessionLeaseLost", heartbeatErr)
			}
		}()
	}
	if !state.CapacityAdmitted {
		state, err = engine.admitCapacity(ctx, journal, state, descriptor)
		if err != nil {
			return result, err
		}
	}
	if !state.CompletedTrials[entry.TrialOrdinal] {
		if err := engine.verifyResidualCapacity(ctx, journal, descriptor, entry.TrialOrdinal); err != nil {
			return result, err
		}
		observed, classification, err := engine.executeAttempt(ctx, journal, descriptor, entry.TrialOrdinal, attemptOptions{ID: attemptID, Kind: "Confirmation"})
		if err != nil {
			return result, err
		}
		finalClass := classification.Class
		if classification.Class == "NetworkFailureCandidate" {
			if classification.Fingerprint == entry.Fingerprint {
				finalClass = "ConfirmedNetworkFailure"
			} else {
				finalClass = "NotReproduced"
			}
		}
		var reduction *fuzzreduce.Result
		if reduce && finalClass == "ConfirmedNetworkFailure" {
			reduction, err = engine.reduce(ctx, journal, descriptor, entry.TrialOrdinal, observed, classification)
			if err != nil {
				return result, err
			}
			result.Reduced = reduction != nil
		}
		attempts, err := engine.capturedAttempts(journal.Records(), entry.TrialOrdinal)
		if err != nil {
			return result, err
		}
		if err := engine.persistEntry(descriptor, entry.TrialOrdinal, finalClass, classification, attempts, reduction); err != nil {
			return result, err
		}
		result.Classification = finalClass
		resultReference, err := engine.Store.PutCanonicalObject("corpus-execution-result", "application/json", result)
		if err != nil {
			return result, err
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "CorpusExecutionClassified", Phase: "Classified", TrialOrdinal: entry.TrialOrdinal, AttemptID: attemptID, Artifacts: []fuzzcorpus.ObjectReference{resultReference}}); err != nil {
			return result, err
		}
		for _, attempt := range attempts {
			if attempt.AttemptKind != "Reduction" {
				if err := engine.teardownAttempt(ctx, journal, entry.TrialOrdinal, attempt); err != nil {
					return result, engine.harnessFailed(journal, "TeardownFailed", err)
				}
			}
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "TrialComplete", Phase: "Complete", TrialOrdinal: entry.TrialOrdinal, AttemptID: attemptID}); err != nil {
			return result, err
		}
	} else {
		result, err = engine.recoverCorpusExecutionResult(journal.Records(), result.RequestDigest)
		if err != nil {
			return result, err
		}
	}
	if err := engine.finishSession(ctx, journal, lease, result.RequestDigest, heartbeat); err != nil {
		return result, err
	}
	return result, nil
}

func (engine *Engine) recoverCorpusExecutionResult(
	records []fuzzcorpus.JournalRecord, requestDigest string,
) (CorpusExecutionResult, error) {
	for _, record := range records {
		if record.Kind != "CorpusExecutionClassified" || len(record.Artifacts) != 1 {
			continue
		}
		data, err := engine.Store.ReadObject(record.Artifacts[0])
		if err != nil {
			return CorpusExecutionResult{}, err
		}
		var result CorpusExecutionResult
		if err := json.Unmarshal(data, &result); err != nil || result.RequestDigest != requestDigest || result.Classification == "" {
			return CorpusExecutionResult{}, errors.New("retained corpus execution result is invalid")
		}
		return result, nil
	}
	return CorpusExecutionResult{}, errors.New("completed corpus execution has no retained result")
}

// Run executes or resumes a finite session from its verified journal.
func (engine *Engine) Run(ctx context.Context, descriptor fuzzplan.Descriptor) (runErr error) {
	if engine.Runtime == nil || engine.Store == nil {
		return errors.New("fuzz runtime and corpus store are required")
	}
	if err := fuzzplan.VerifyDescriptor(descriptor); err != nil {
		return err
	}
	lock, err := engine.Store.AcquireLock(descriptor.Digest)
	if err != nil {
		return err
	}
	defer lock.Release()
	journal, err := engine.Store.OpenOrCreateJournal(descriptor.Digest)
	if err != nil {
		return err
	}
	state, err := recoverState(journal.Records())
	if err != nil {
		return err
	}
	if state.SessionComplete {
		return engine.verifySessionReport(journal.Records(), descriptor.Digest)
	}
	if len(journal.Records()) == 0 {
		descriptorReference, putErr := engine.Store.PutExactIntegerObject(
			"session-descriptor", "application/json", descriptor,
		)
		if putErr != nil {
			return putErr
		}
		artifacts := []fuzzcorpus.ObjectReference{descriptorReference}
		for _, advisory := range descriptor.Advisories {
			data, advisoryErr := fuzzplan.AdvisoryObjectBytes(advisory)
			if advisoryErr != nil {
				return advisoryErr
			}
			reference, advisoryErr := engine.Store.PutObject(
				"advisory-trial-"+strconv.Itoa(int(advisory.TrialOrdinal)),
				"application/json", data,
			)
			if advisoryErr != nil {
				return advisoryErr
			}
			if reference.Digest != advisory.Digest {
				return errors.New("retained advisory differs from the sealed decision input")
			}
			artifacts = append(artifacts, reference)
		}
		if _, appendErr := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "SessionPlanned", Phase: "Planned",
			Artifacts: artifacts,
		}); appendErr != nil {
			return appendErr
		}
	}
	ctx, cancel, err := engine.sessionContext(ctx, journal.Records(), descriptor.MaxDuration.Duration)
	if err != nil {
		return err
	}
	defer cancel()
	var lease fuzzcorpus.ResourceIdentity
	var heartbeat *leaseHeartbeat
	if state.LeaseReleaseIntended {
		if state.Lease == nil {
			return errors.New("session cleanup has no journaled lease identity")
		}
		lease = *state.Lease
	} else {
		lease, err = engine.acquireOrResumeLease(ctx, journal, state, descriptor.Digest)
		if err != nil {
			return err
		}
		ctx, heartbeat = engine.startLeaseHeartbeat(ctx, lease, descriptor.Digest)
		defer func() {
			heartbeat.Stop()
			if heartbeatErr := heartbeat.TakeError(); heartbeatErr != nil {
				runErr = engine.harnessFailed(journal, "SessionLeaseLost", heartbeatErr)
			}
		}()
	}
	if !state.CapacityAdmitted {
		state, err = engine.admitCapacity(ctx, journal, state, descriptor)
		if err != nil {
			return err
		}
	}
	for _, trial := range descriptor.Trials {
		if state.CompletedTrials[trial.Ordinal] {
			continue
		}
		if err := engine.verifyResidualCapacity(ctx, journal, descriptor, trial.Ordinal); err != nil {
			return err
		}
		source, classification, err := engine.executeAttempt(
			ctx, journal, descriptor, trial.Ordinal,
			attemptOptions{ID: "source", Kind: "Source"},
		)
		if err != nil {
			return err
		}
		finalClass := classification.Class
		if classification.Class == "NetworkFailureCandidate" {
			matches := int32(0)
			for attempt := int32(1); attempt <= descriptor.Confirmation.MaxAttempts; attempt++ {
				if err := engine.verifyResidualCapacity(ctx, journal, descriptor, trial.Ordinal); err != nil {
					return err
				}
				confirmationID := "confirm-" + strconv.Itoa(int(attempt))
				_, observed, runErr := engine.executeAttempt(
					ctx, journal, descriptor, trial.Ordinal, attemptOptions{
						ID: confirmationID, Kind: "Confirmation", Source: &source,
					},
				)
				if runErr != nil {
					return runErr
				}
				if observed.Class == "NetworkFailureCandidate" &&
					observed.Fingerprint == classification.Fingerprint {
					matches++
					if matches >= descriptor.Confirmation.RequiredMatches {
						finalClass = "ConfirmedNetworkFailure"
						break
					}
					continue
				}
				if observed.Class == "HarnessFailed" || observed.Class == "Inconclusive" {
					finalClass = observed.Class
					break
				}
			}
			if finalClass == "NetworkFailureCandidate" {
				finalClass = "NotReproduced"
			}
		}
		var reduction *fuzzreduce.Result
		if finalClass == "ConfirmedNetworkFailure" && descriptor.Reduction.Enabled {
			result, reduceErr := engine.reduce(
				ctx, journal, descriptor, trial.Ordinal, source, classification,
			)
			if reduceErr != nil {
				return reduceErr
			}
			reduction = result
		}
		attempts, err := engine.capturedAttempts(journal.Records(), trial.Ordinal)
		if err != nil {
			return err
		}
		if err := engine.persistEntry(
			descriptor, trial.Ordinal, finalClass, classification, attempts, reduction,
		); err != nil {
			return err
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "TrialClassified", Phase: "Classified", TrialOrdinal: trial.Ordinal,
			AttemptID: "source",
		}); err != nil {
			return err
		}
		for _, attempt := range attempts {
			if attempt.AttemptKind == "Reduction" {
				continue
			}
			if err := engine.teardownAttempt(ctx, journal, trial.Ordinal, attempt); err != nil {
				return engine.harnessFailed(journal, "TeardownFailed", err)
			}
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "TrialComplete", Phase: "Complete", TrialOrdinal: trial.Ordinal,
			AttemptID: "source",
		}); err != nil {
			return err
		}
		state.CompletedTrials[trial.Ordinal] = true
	}
	return engine.finishSession(ctx, journal, lease, descriptor.Digest, heartbeat)
}

func (engine *Engine) finishSession(
	ctx context.Context, journal *fuzzcorpus.Journal,
	lease fuzzcorpus.ResourceIdentity, holder string, heartbeat *leaseHeartbeat,
) error {
	state, err := recoverState(journal.Records())
	if err != nil {
		return err
	}
	if !state.CleanupStarted {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "SessionCleanupStarted", Phase: "Capturing", Resources: state.Reservations}); err != nil {
			return err
		}
	}
	if !state.ReservationsReleased {
		if err := engine.Runtime.ReleaseReservation(ctx, state.Reservations); err != nil {
			return engine.harnessFailed(journal, "ReservationReleaseFailed", err)
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "ReservationsReleased", Phase: "Capturing", Resources: state.Reservations}); err != nil {
			return err
		}
	}
	if heartbeat != nil {
		latest, _ := heartbeat.Stop()
		if heartbeatErr := heartbeat.TakeError(); heartbeatErr != nil {
			return engine.harnessFailed(journal, "SessionLeaseLost", heartbeatErr)
		}
		lease = latest
	}
	if !state.LeaseReleaseIntended {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "IntentReleaseSessionLease", Phase: "Capturing", Resources: []fuzzcorpus.ResourceIdentity{lease}}); err != nil {
			return err
		}
	}
	if !state.LeaseReleased {
		if err := engine.Runtime.ReleaseSession(ctx, lease, holder); err != nil {
			return engine.harnessFailed(journal, "SessionLeaseReleaseFailed", err)
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "SessionLeaseReleased", Phase: "Capturing", Resources: []fuzzcorpus.ResourceIdentity{lease}}); err != nil {
			return err
		}
	}
	state, err = recoverState(journal.Records())
	if err != nil {
		return err
	}
	if !state.ReportRetained {
		report, err := engine.buildSessionReport(journal.Records(), holder)
		if err != nil {
			return err
		}
		reference, err := engine.Store.PutCanonicalObject("session-report", "application/json", report)
		if err != nil {
			return err
		}
		if err := engine.Store.PutReportPointer(holder, reference); err != nil {
			return err
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "SessionReportRetained", Phase: "Capturing",
			Artifacts: []fuzzcorpus.ObjectReference{reference},
		}); err != nil {
			return err
		}
	} else if err := engine.verifySessionReport(journal.Records(), holder); err != nil {
		return err
	}
	_, err = journal.Append(fuzzcorpus.JournalRecord{Kind: "SessionComplete", Phase: "Complete"})
	return err
}

func (engine *Engine) buildSessionReport(
	records []fuzzcorpus.JournalRecord, sessionDigest string,
) (sessionReport, error) {
	if len(records) == 0 {
		return sessionReport{}, errors.New("cannot report an empty session journal")
	}
	report := sessionReport{
		SchemaVersion: "stacks-attacknet-fuzz-session-report/v1",
		SessionDigest: sessionDigest, Status: "Complete",
		GeneratedFromSequence: records[len(records)-1].Sequence,
		GeneratedFromDigest:   records[len(records)-1].Digest,
		TransitionCounts:      map[string]int32{},
	}
	completed := map[int32]struct{}{}
	for _, record := range records {
		report.TransitionCounts[record.Kind]++
		if record.Kind == "TrialComplete" {
			completed[record.TrialOrdinal] = struct{}{}
		}
		if record.Kind == "CapacityAdmitted" {
			report.ReservationCount = len(record.Resources)
			if len(record.Artifacts) == 1 {
				report.CapacityAdmissionDigest = record.Artifacts[0].Digest
			}
		}
	}
	for ordinal := range completed {
		report.CompletedTrials = append(report.CompletedTrials, ordinal)
	}
	sort.Slice(report.CompletedTrials, func(i, j int) bool { return report.CompletedTrials[i] < report.CompletedTrials[j] })
	entries, err := engine.Store.Entries()
	if err != nil {
		return report, err
	}
	for _, entry := range entries {
		if entry.SessionDigest != sessionDigest {
			continue
		}
		report.CorpusEntries = append(report.CorpusEntries, sessionEntrySummary{
			Digest: entry.Digest, Fingerprint: entry.Fingerprint,
			Classification: entry.Classification, TrialOrdinal: entry.TrialOrdinal,
		})
	}
	return report, nil
}

func (engine *Engine) verifySessionReport(
	records []fuzzcorpus.JournalRecord, sessionDigest string,
) error {
	pointer, err := engine.Store.Report(sessionDigest)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Kind == "SessionReportRetained" && len(record.Artifacts) == 1 &&
			record.Artifacts[0].Digest == pointer.Report.Digest {
			return nil
		}
	}
	return errors.New("session report pointer differs from its journal record")
}

type attemptOptions struct {
	ID            string
	Kind          string
	Source        *ObservedAttempt
	Reduction     *fuzzreduce.Candidate
	EvidenceLimit int64
}

func (engine *Engine) executeAttempt(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	descriptor fuzzplan.Descriptor,
	ordinal int32,
	options attemptOptions,
) (ObservedAttempt, Classification, error) {
	materialized, err := fuzzplan.MaterializeTrial(
		descriptor, ordinal, options.ID, options.Kind, descriptor.Network.Template.Namespace,
	)
	if err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	if options.Source != nil && options.Reduction == nil {
		expectedAssertion, expectedStatus := expectedFailure(options.Source.Result)
		materialized.Run.Spec.Replay = attacknetv1beta1.ReplaySpec{
			Enabled: true, SourceRunRef: options.Source.Run.Name,
			DescriptorURI:    "k8s://attacknetruns/" + options.Source.Run.Name + "/resolved-schedule",
			DescriptorDigest: options.Source.ScheduleDigest, AttemptID: options.ID,
			ExpectedAssertion: expectedAssertion, ExpectedStatus: expectedStatus,
			RequireSameResolvedImages: true, VerifyExpectedFailure: expectedAssertion != "",
		}
	}
	if options.Source != nil && options.Reduction != nil {
		expectedAssertion, expectedStatus := expectedFailure(options.Source.Result)
		if expectedAssertion == "" {
			return ObservedAttempt{}, Classification{}, errors.New("reduction source has no violated protocol assertion")
		}
		materialized.Run.Spec.Minimization = attacknetv1beta1.MinimizationSpec{
			Enabled: true, Strategy: "DeltaDebug", MaxAttempts: 1,
			RequireFreshNetwork: true, SourceRunRef: options.Source.Run.Name,
			SourceScheduleDigest: options.Source.ScheduleDigest,
			AttemptID:            options.ID, CandidateDigest: options.Reduction.Digest,
			ExpectedAssertion: expectedAssertion, ExpectedStatus: expectedStatus,
			Retained: options.Reduction.Retained,
		}
	}
	records := journal.Records()
	expectedPolicies, expectedTemplates, expectedEvidence, expectedNetwork, expectedRun := observedIdentities(records, ordinal, options.ID)
	retained, retainedClassification, found, err := engine.recoverAttempt(
		records, ordinal, options.ID,
	)
	if err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	if found {
		if expectedNetwork == nil || expectedRun == nil ||
			retained.Network.UID != expectedNetwork.UID || retained.Run.UID != expectedRun.UID ||
			!sameResourceIdentities(retained.Policies, expectedPolicies) ||
			!sameResourceIdentities(retained.Templates, expectedTemplates) ||
			!sameResourceIdentities(retained.EvidencePlane, expectedEvidence) {
			return ObservedAttempt{}, Classification{}, errors.New("retained attempt identity differs from its journal")
		}
		if !hasAttemptRecord(records, "NetworkSuspended", ordinal, options.ID) {
			if err := engine.Runtime.SuspendNetwork(ctx, retained.Network); err != nil {
				return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "NetworkSuspendFailed", err)
			}
			if _, err := journal.Append(fuzzcorpus.JournalRecord{
				Kind: "NetworkSuspended", Phase: "Capturing", TrialOrdinal: ordinal,
				AttemptID: options.ID, Resources: []fuzzcorpus.ResourceIdentity{retained.Network},
			}); err != nil {
				return ObservedAttempt{}, Classification{}, err
			}
		}
		if !hasAttemptRecord(records, "EvidencePlaneReleased", ordinal, options.ID) {
			if err := engine.Runtime.ReleaseEvidencePlane(ctx, retained.EvidencePlane); err != nil {
				return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "EvidencePlaneReleaseFailed", err)
			}
			if _, err := journal.Append(fuzzcorpus.JournalRecord{
				Kind: "EvidencePlaneReleased", Phase: "Capturing", TrialOrdinal: ordinal,
				AttemptID: options.ID, Resources: retained.EvidencePlane,
			}); err != nil {
				return ObservedAttempt{}, Classification{}, err
			}
		}
		return retained, retainedClassification, nil
	}
	if expectedPolicies == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentCreatePolicies", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	policyByName := make(map[string]fuzzcorpus.ResourceIdentity, len(expectedPolicies))
	for _, policy := range expectedPolicies {
		policyByName[policy.Name] = policy
	}
	policies := make([]fuzzcorpus.ResourceIdentity, 0, len(materialized.Policies))
	for index := range materialized.Policies {
		desired := &materialized.Policies[index]
		var expected *fuzzcorpus.ResourceIdentity
		if value, found := policyByName[desired.Name]; found {
			copy := value
			expected = &copy
		} else if expectedPolicies != nil {
			return ObservedAttempt{}, Classification{}, errors.New("journaled burnchain policy inventory differs from the descriptor")
		}
		identity, err := engine.Runtime.EnsurePolicy(ctx, desired, expected, expectedRun != nil)
		if err != nil {
			return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "PolicyIdentityChanged", err)
		}
		policies = append(policies, identity)
	}
	if len(policies) != len(expectedPolicies) && expectedPolicies != nil {
		return ObservedAttempt{}, Classification{}, errors.New("journaled burnchain policy count differs from the descriptor")
	}
	if expectedPolicies == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "PoliciesObserved", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID, Resources: policies,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	if expectedTemplates == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentCreateTemplates", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	templates, err := engine.Runtime.EnsureTemplates(
		ctx, materialized.FaultTemplates, materialized.UpgradeTemplates, expectedTemplates,
	)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "TemplateIdentityChanged", err)
	}
	if err := bindTemplateIdentities(&materialized, templates); err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "TemplateIdentityChanged", err)
	}
	if expectedTemplates == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "TemplatesObserved", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID, Resources: templates,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	if expectedNetwork == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentCreateNetwork", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	network, err := engine.Runtime.EnsureNetwork(ctx, &materialized.Network, expectedNetwork)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "NetworkIdentityChanged", err)
	}
	if expectedNetwork == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "NetworkObserved", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID,
			Resources: []fuzzcorpus.ResourceIdentity{network},
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	if err := engine.Runtime.WaitNetworkReady(ctx, network); err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "NetworkNotReady", err)
	}
	if expectedEvidence == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentCreateEvidencePlane", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	evidencePlane, err := engine.Runtime.EnsureEvidencePlane(ctx, network, expectedEvidence)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "EvidencePlaneUnavailable", err)
	}
	if len(evidencePlane) == 0 {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "EvidencePlaneUnavailable", errors.New("evidence plane has no identity-bound resources"))
	}
	if expectedEvidence == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "EvidencePlaneObserved", Phase: "TrialPreparing",
			TrialOrdinal: ordinal, AttemptID: options.ID, Resources: evidencePlane,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	if expectedRun == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentCreateRun", Phase: "TrialRunning",
			TrialOrdinal: ordinal, AttemptID: options.ID,
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	run, err := engine.Runtime.EnsureRun(ctx, &materialized.Run, expectedRun)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "RunIdentityChanged", err)
	}
	if expectedRun == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "RunObserved", Phase: "TrialRunning",
			TrialOrdinal: ordinal, AttemptID: options.ID,
			Resources: []fuzzcorpus.ResourceIdentity{run},
		}); err != nil {
			return ObservedAttempt{}, Classification{}, err
		}
	}
	observed, err := engine.Runtime.WaitRunTerminal(ctx, run)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "RunObservationFailed", err)
	}
	// A fault backend may report its child terminal before the restored actor
	// identity is admitted again. Capture only after the topology controller
	// re-establishes a complete inventory; otherwise a transient restoration can
	// produce two different trusted digests within one evidence bundle.
	if err := engine.Runtime.WaitNetworkReady(ctx, network); err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "NetworkRecoveryUnavailable", err)
	}
	observed.Policies, observed.Templates = policies, templates
	observed.EvidencePlane, observed.Network, observed.Run = evidencePlane, network, run
	observed.AttemptID = options.ID
	observed.AttemptKind = options.Kind
	if err := engine.verifyResidualCapacity(ctx, journal, descriptor, ordinal); err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	evidenceLimit := options.EvidenceLimit
	if evidenceLimit == 0 {
		evidenceLimit = descriptor.Corpus.MaximumBytes
	}
	observed, err = engine.Runtime.Capture(ctx, observed, evidenceLimit)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "EvidenceCaptureFailed", err)
	}
	if bytes := artifactBytes(observed.Artifacts); bytes > evidenceLimit {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(
			journal, "EvidenceBudgetExceeded",
			fmt.Errorf("captured %d evidence bytes with a %d-byte limit", bytes, evidenceLimit),
		)
	}
	classification, err := Classify(observed.Result)
	if err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "ClassificationFailed", err)
	}
	observed.Classification = classification.Class
	if err := engine.retainAttempt(journal, ordinal, options.ID, observed); err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	if err := engine.Runtime.SuspendNetwork(ctx, network); err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "NetworkSuspendFailed", err)
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: "NetworkSuspended", Phase: "Capturing", TrialOrdinal: ordinal,
		AttemptID: options.ID, Resources: []fuzzcorpus.ResourceIdentity{network},
	}); err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	if err := engine.Runtime.ReleaseEvidencePlane(ctx, evidencePlane); err != nil {
		return ObservedAttempt{}, Classification{}, engine.harnessFailed(journal, "EvidencePlaneReleaseFailed", err)
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: "EvidencePlaneReleased", Phase: "Capturing", TrialOrdinal: ordinal,
		AttemptID: options.ID, Resources: evidencePlane,
	}); err != nil {
		return ObservedAttempt{}, Classification{}, err
	}
	return observed, classification, nil
}

func (engine *Engine) retainAttempt(
	journal *fuzzcorpus.Journal, ordinal int32, attemptID string, attempt ObservedAttempt,
) error {
	artifactReferences := make([]fuzzcorpus.ObjectReference, 0, len(attempt.Artifacts))
	for _, artifact := range attempt.Artifacts {
		reference, err := engine.Store.PutObject(
			artifact.Name,
			artifact.ContentType, artifact.Data,
		)
		if err != nil {
			return err
		}
		artifactReferences = append(artifactReferences, reference)
	}
	if len(artifactReferences) == 0 {
		return errors.New("captured attempt has no retained artifacts")
	}
	view := attempt
	view.Artifacts = nil
	retained := retainedAttempt{
		SchemaVersion: retainedAttemptSchema, Attempt: view,
		Artifacts: artifactReferences,
	}
	observation, err := engine.Store.PutCanonicalObject(
		"attempt-observation-"+attemptID, "application/json", retained,
	)
	if err != nil {
		return err
	}
	references := append([]fuzzcorpus.ObjectReference{observation}, artifactReferences...)
	_, err = journal.Append(fuzzcorpus.JournalRecord{
		Kind: "AttemptCaptured", Phase: "Capturing", TrialOrdinal: ordinal,
		AttemptID: attemptID, Resources: attemptResources(attempt),
		Artifacts: references,
	})
	return err
}

func (engine *Engine) recoverAttempt(
	records []fuzzcorpus.JournalRecord, ordinal int32, attemptID string,
) (ObservedAttempt, Classification, bool, error) {
	for _, record := range records {
		if record.Kind != "AttemptCaptured" || record.TrialOrdinal != ordinal ||
			record.AttemptID != attemptID {
			continue
		}
		if len(record.Artifacts) < 2 || len(record.Resources) < 3 {
			return ObservedAttempt{}, Classification{}, false, errors.New("captured-attempt journal record is incomplete")
		}
		data, err := engine.Store.ReadObject(record.Artifacts[0])
		if err != nil {
			return ObservedAttempt{}, Classification{}, false, err
		}
		var retained retainedAttempt
		if err := json.Unmarshal(data, &retained); err != nil ||
			retained.SchemaVersion != retainedAttemptSchema ||
			len(retained.Artifacts) != len(record.Artifacts)-1 {
			return ObservedAttempt{}, Classification{}, false, errors.New("retained attempt object is invalid")
		}
		if !sameResourceIdentities(record.Resources, attemptResources(retained.Attempt)) {
			return ObservedAttempt{}, Classification{}, false, errors.New("retained resource inventory differs from journal")
		}
		for index, reference := range retained.Artifacts {
			if reference != record.Artifacts[index+1] {
				return ObservedAttempt{}, Classification{}, false, errors.New("retained artifact inventory differs from journal")
			}
			artifact, err := engine.Store.ReadObject(reference)
			if err != nil {
				return ObservedAttempt{}, Classification{}, false, err
			}
			retained.Attempt.Artifacts = append(retained.Attempt.Artifacts, Artifact{
				Name: reference.Name, ContentType: reference.ContentType, Data: artifact,
			})
		}
		classification, err := Classify(retained.Attempt.Result)
		if err != nil || classification.Class != retained.Attempt.Classification {
			return ObservedAttempt{}, Classification{}, false, errors.New("retained attempt classification mismatch")
		}
		return retained.Attempt, classification, true, nil
	}
	return ObservedAttempt{}, Classification{}, false, nil
}

func hasAttemptRecord(
	records []fuzzcorpus.JournalRecord, kind string, ordinal int32, attemptID string,
) bool {
	for _, record := range records {
		if record.Kind == kind && record.TrialOrdinal == ordinal && record.AttemptID == attemptID {
			return true
		}
	}
	return false
}

func (engine *Engine) capturedAttempts(
	records []fuzzcorpus.JournalRecord, ordinal int32,
) ([]ObservedAttempt, error) {
	result := []ObservedAttempt{}
	seen := map[string]bool{}
	for _, record := range records {
		if record.Kind != "AttemptCaptured" || record.TrialOrdinal != ordinal || seen[record.AttemptID] {
			continue
		}
		attempt, _, found, err := engine.recoverAttempt(records, ordinal, record.AttemptID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("captured attempt disappeared from verified journal")
		}
		seen[record.AttemptID] = true
		result = append(result, attempt)
	}
	if len(result) == 0 {
		return nil, errors.New("trial has no captured attempts")
	}
	return result, nil
}

func (engine *Engine) verifyResidualCapacity(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	descriptor fuzzplan.Descriptor,
	ordinal int32,
) error {
	snapshot, err := engine.Runtime.Capacity(ctx, descriptor)
	if err != nil {
		return engine.harnessFailed(journal, "CapacityRecheckUnavailable", err)
	}
	policy := descriptor.Capacity
	policy.StorageEscrowBytes = 0
	policy.EvidenceEscrowBytes = 0
	receipt, err := EvaluateCapacity(policy, snapshot)
	if err != nil {
		return engine.harnessFailed(journal, "CapacityRecheckUnavailable", err)
	}
	reference, err := engine.Store.PutCanonicalObject(
		"capacity-recheck", "application/json", receipt,
	)
	if err != nil {
		return err
	}
	phase, kind := "CapacityAdmitted", "CapacityRechecked"
	if !receipt.Admitted {
		phase, kind = "Paused", "CapacityDriftDetected"
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: kind, Phase: phase, TrialOrdinal: ordinal,
		Artifacts: []fuzzcorpus.ObjectReference{reference},
	}); err != nil {
		return err
	}
	if !receipt.Admitted {
		return fmt.Errorf("capacity drift: %s", receipt.Reason)
	}
	return nil
}

func (engine *Engine) admitCapacity(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	state recoveredState,
	descriptor fuzzplan.Descriptor,
) (recoveredState, error) {
	snapshot, err := engine.Runtime.Capacity(ctx, descriptor)
	if err != nil {
		return state, engine.harnessFailed(journal, "CapacityUnavailable", err)
	}
	receipt, err := EvaluateCapacity(descriptor.Capacity, snapshot)
	if err != nil {
		return state, engine.harnessFailed(journal, "CapacityUnavailable", err)
	}
	reference, err := engine.Store.PutCanonicalObject("capacity-admission", "application/json", receipt)
	if err != nil {
		return state, err
	}
	if !receipt.Admitted {
		if _, appendErr := journal.Append(fuzzcorpus.JournalRecord{Kind: "CapacityRejected", Phase: "Paused", Artifacts: []fuzzcorpus.ObjectReference{reference}}); appendErr != nil {
			return state, appendErr
		}
		return state, fmt.Errorf("capacity unavailable: %s", receipt.Reason)
	}
	reservations, err := engine.Runtime.Reserve(ctx, descriptor)
	if err != nil {
		return state, engine.harnessFailed(journal, "CapacityUnavailable", err)
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{Kind: "CapacityAdmitted", Phase: "CapacityAdmitted", Resources: reservations, Artifacts: []fuzzcorpus.ObjectReference{reference}}); err != nil {
		// The reservation is not recoverable from the journal until the
		// CapacityAdmitted record is durable. Roll it back synchronously so a
		// corpus-write failure cannot strand local or PVC-backed escrow.
		if releaseErr := engine.Runtime.ReleaseReservation(ctx, reservations); releaseErr != nil {
			return state, errors.Join(err, fmt.Errorf("roll back unjournaled capacity reservation: %w", releaseErr))
		}
		return state, err
	}
	state.CapacityAdmitted = true
	state.Reservations = reservations
	return state, nil
}

func (engine *Engine) reduce(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	descriptor fuzzplan.Descriptor,
	ordinal int32,
	source ObservedAttempt,
	classification Classification,
) (*fuzzreduce.Result, error) {
	materialized, err := fuzzplan.MaterializeTrial(
		descriptor, ordinal, "source", "Source", descriptor.Network.Template.Namespace,
	)
	if err != nil {
		return nil, err
	}
	campaigns := map[string]attacknetv1beta1.FaultCampaignSpec{}
	for _, template := range descriptor.Templates {
		if template.FaultSpec != nil {
			campaigns[template.ID] = *template.FaultSpec.DeepCopy()
		}
	}
	reductionSource, err := fuzzreduce.SourceFromRun(materialized.Run.Spec.Executions, campaigns)
	if err != nil {
		// Mixed-version schedules remain valuable corpus entries, but automatic
		// removal would change version context rather than only fault material.
		return nil, nil
	}
	reducer, err := fuzzreduce.New(reductionSource, descriptor.Reduction.MaxAttempts)
	if err != nil {
		return nil, err
	}
	if err := engine.reconcileReductionTeardown(ctx, journal, ordinal); err != nil {
		return nil, engine.harnessFailed(journal, "ReductionTeardownFailed", err)
	}
	if err := engine.restoreReduction(journal.Records(), reducer, ordinal); err != nil {
		return nil, err
	}
	if !hasTrialRecord(journal.Records(), "ReductionStarted", ordinal) {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "ReductionStarted", Phase: "Reducing", TrialOrdinal: ordinal,
		}); err != nil {
			return nil, err
		}
	}
	reductionCtx, cancel, err := engine.reductionContext(
		ctx, journal.Records(), ordinal, descriptor.Reduction.MaxDuration.Duration,
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	retained, err := engine.capturedAttempts(journal.Records(), ordinal)
	if err != nil {
		return nil, err
	}
	var evidenceUsed int64
	for _, attempt := range retained {
		if attempt.AttemptKind == "Reduction" {
			evidenceUsed += artifactBytes(attempt.Artifacts)
		}
	}
	for {
		remaining := descriptor.Reduction.MaxEvidenceBytes - evidenceUsed
		if remaining < fuzzplan.MinimumReductionEvidenceBytes {
			break
		}
		candidate, err := reducer.Next()
		if err != nil || candidate == nil {
			if err != nil {
				return nil, err
			}
			break
		}
		candidateReference, err := engine.Store.PutCanonicalObject(
			"reduction-candidate", "application/json", candidate,
		)
		if err != nil {
			return nil, err
		}
		attemptID := fmt.Sprintf("reduce-%03d", candidate.Attempt)
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "ReductionCandidatePlanned", Phase: "Reducing",
			TrialOrdinal: ordinal, AttemptID: attemptID,
			Artifacts: []fuzzcorpus.ObjectReference{candidateReference},
		}); err != nil {
			return nil, err
		}
		if err := engine.verifyResidualCapacity(reductionCtx, journal, descriptor, ordinal); err != nil {
			if errors.Is(reductionCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				break
			}
			return nil, err
		}
		observed, result, err := engine.executeAttempt(
			reductionCtx, journal, descriptor, ordinal, attemptOptions{
				ID: attemptID, Kind: "Reduction", Source: &source, Reduction: candidate,
				EvidenceLimit: remaining,
			},
		)
		if err != nil {
			if errors.Is(reductionCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				break
			}
			return nil, err
		}
		evidenceUsed += artifactBytes(observed.Artifacts)
		outcome := fuzzreduce.OutcomeNotReproduced
		switch {
		case result.Class == "NetworkFailureCandidate" && result.Fingerprint == classification.Fingerprint:
			outcome = fuzzreduce.OutcomeReproduced
		case result.Class == "Inconclusive" || result.Class == "HarnessFailed":
			outcome = fuzzreduce.OutcomeInconclusive
		}
		if err := reducer.Record(outcome); err != nil {
			return nil, err
		}
		outcomeReference, err := engine.Store.PutCanonicalObject(
			"reduction-outcome", "application/json",
			fuzzreduce.Attempt{Candidate: *candidate, Outcome: outcome},
		)
		if err != nil {
			return nil, err
		}
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "ReductionOutcomeRecorded", Phase: "Reducing",
			TrialOrdinal: ordinal, AttemptID: attemptID,
			Artifacts: []fuzzcorpus.ObjectReference{outcomeReference},
		}); err != nil {
			return nil, err
		}
		if err := engine.teardownAttempt(reductionCtx, journal, ordinal, observed); err != nil {
			return nil, engine.harnessFailed(journal, "ReductionTeardownFailed", err)
		}
	}
	result := reducer.Result()
	reference, err := engine.Store.PutCanonicalObject(
		"reduction-graph", "application/json", result,
	)
	if err != nil {
		return nil, err
	}
	if _, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: "ReductionComplete", Phase: "Classified", TrialOrdinal: ordinal,
		Artifacts: []fuzzcorpus.ObjectReference{reference},
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

// reconcileReductionTeardown completes cleanup journaled before a crash.
func (engine *Engine) reconcileReductionTeardown(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	ordinal int32,
) error {
	attempts, err := engine.capturedAttempts(journal.Records(), ordinal)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		if attempt.AttemptKind != "Reduction" ||
			hasAttemptRecord(journal.Records(), "AttemptTeardownComplete", ordinal, attempt.AttemptID) {
			continue
		}
		if err := engine.teardownAttempt(ctx, journal, ordinal, attempt); err != nil {
			return err
		}
	}
	return nil
}

func artifactBytes(artifacts []Artifact) int64 {
	var total int64
	for _, artifact := range artifacts {
		if int64(len(artifact.Data)) > math.MaxInt64-total {
			return math.MaxInt64
		}
		total += int64(len(artifact.Data))
	}
	return total
}

func (engine *Engine) restoreReduction(
	records []fuzzcorpus.JournalRecord,
	reducer *fuzzreduce.Reducer,
	ordinal int32,
) error {
	for _, record := range records {
		if record.Kind != "ReductionOutcomeRecorded" || record.TrialOrdinal != ordinal {
			continue
		}
		if len(record.Artifacts) != 1 {
			return errors.New("reduction outcome journal record is incomplete")
		}
		data, err := engine.Store.ReadObject(record.Artifacts[0])
		if err != nil {
			return err
		}
		var prior fuzzreduce.Attempt
		if err := json.Unmarshal(data, &prior); err != nil {
			return err
		}
		next, err := reducer.Next()
		if err != nil || next == nil || next.Digest != prior.Candidate.Digest ||
			next.Attempt != prior.Candidate.Attempt {
			return errors.New("reduction journal differs from deterministic reducer state")
		}
		if err := reducer.Record(prior.Outcome); err != nil {
			return err
		}
	}
	return nil
}

func (engine *Engine) teardownAttempt(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	ordinal int32,
	attempt ObservedAttempt,
) error {
	records := journal.Records()
	if hasAttemptRecord(records, "AttemptTeardownComplete", ordinal, attempt.AttemptID) {
		return nil
	}
	if !hasAttemptRecord(records, "IntentTeardownAttempt", ordinal, attempt.AttemptID) {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "IntentTeardownAttempt", Phase: "Capturing", TrialOrdinal: ordinal,
			AttemptID: attempt.AttemptID, Resources: attemptResources(attempt),
		}); err != nil {
			return err
		}
	}
	if err := engine.Runtime.Teardown(ctx, attempt); err != nil {
		return err
	}
	_, err := journal.Append(fuzzcorpus.JournalRecord{
		Kind: "AttemptTeardownComplete", Phase: "Capturing", TrialOrdinal: ordinal,
		AttemptID: attempt.AttemptID, Resources: attemptResources(attempt),
	})
	return err
}

func expectedFailure(result TrialResult) (string, string) {
	if len(result.ViolatedAssertions) == 0 {
		return "", ""
	}
	value := result.ViolatedAssertions[0]
	separator := strings.LastIndex(value, ":")
	slash := strings.Index(value, "/")
	if separator <= slash+1 || slash < 0 {
		return "", ""
	}
	return value[slash+1 : separator], value[separator+1:]
}

func (engine *Engine) persistEntry(
	descriptor fuzzplan.Descriptor,
	ordinal int32,
	class string,
	classification Classification,
	attempts []ObservedAttempt,
	reduction *fuzzreduce.Result,
) error {
	objects := []fuzzcorpus.ObjectReference{}
	descriptorRef, err := engine.Store.PutExactIntegerObject(
		"session-descriptor", "application/json", descriptor,
	)
	if err != nil {
		return err
	}
	objects = append(objects, descriptorRef)
	corpusAttempts := make([]fuzzcorpus.Attempt, 0, len(attempts))
	for index, attempt := range attempts {
		evidenceDigest := ""
		artifactReferences := []fuzzcorpus.ObjectReference{}
		for _, artifact := range attempt.Artifacts {
			reference, err := engine.Store.PutObject(
				fmt.Sprintf("attempt-%02d-%s", index+1, artifact.Name),
				artifact.ContentType, artifact.Data,
			)
			if err != nil {
				return err
			}
			objects = append(objects, reference)
			artifactReferences = append(artifactReferences, reference)
			if artifact.Name == "evidence-manifest" {
				evidenceDigest = reference.Digest
			}
		}
		if evidenceDigest == "" {
			return errors.New("attempt lacks a sealed evidence-manifest artifact")
		}
		view := attempt
		view.Artifacts = nil
		observation, err := engine.Store.PutCanonicalObject(
			fmt.Sprintf("attempt-%02d-observation", index+1), "application/json",
			retainedAttempt{SchemaVersion: retainedAttemptSchema, Attempt: view, Artifacts: artifactReferences},
		)
		if err != nil {
			return err
		}
		objects = append(objects, observation)
		corpusAttempts = append(corpusAttempts, fuzzcorpus.Attempt{
			ID: attempt.AttemptID, Kind: attempt.AttemptKind,
			NetworkUID: attempt.Network.UID, RunUID: attempt.Run.UID,
			ScheduleDigest: attempt.ScheduleDigest, Classification: attempt.Classification,
			EvidenceDigest: evidenceDigest,
		})
	}
	advisoryReferences := []fuzzcorpus.AdvisoryReference{}
	trial := descriptor.Trials[ordinal-1]
	if trial.AdvisoryDigest != "" {
		var artifact fuzzplan.AdvisoryArtifact
		for _, candidate := range descriptor.Advisories {
			if candidate.Digest == trial.AdvisoryDigest {
				artifact = candidate
				break
			}
		}
		data, err := fuzzplan.AdvisoryObjectBytes(artifact)
		if err != nil {
			return err
		}
		reference, err := engine.Store.PutObject(
			"advisory-trial-"+strconv.Itoa(int(ordinal)), "application/json", data,
		)
		if err != nil {
			return err
		}
		if reference.Digest != trial.AdvisoryDigest {
			return errors.New("retained advisory object differs from decision input")
		}
		objects = append(objects, reference)
		for _, receipt := range trial.Receipts {
			if receipt.AdvisoryDigest == trial.AdvisoryDigest {
				advisoryReferences = append(advisoryReferences, fuzzcorpus.AdvisoryReference{
					ObjectDigest: reference.Digest, DecisionDomain: receipt.Domain,
					ReceiptDigest: receipt.Digest,
				})
			}
		}
	}
	reductionDigests := []string{}
	if reduction != nil {
		reference, putErr := engine.Store.PutCanonicalObject(
			"reduction-graph", "application/json", reduction,
		)
		if putErr != nil {
			return putErr
		}
		objects = append(objects, reference)
		reductionDigests = append(reductionDigests, reference.Digest)
	}
	_, err = engine.Store.PutEntry(fuzzcorpus.Entry{
		SchemaVersion: fuzzcorpus.EntrySchema,
		Fingerprint:   classification.Fingerprint, Classification: class,
		SessionDigest: descriptor.Digest, TrialOrdinal: ordinal,
		SourceRun: attempts[0].Run.Name,
		ReplayCommand: []string{
			"attacknet", "corpus", "replay", "--corpus", descriptor.Corpus.Root,
			classification.Fingerprint,
		},
		Objects: objects, Attempts: corpusAttempts, Advisories: advisoryReferences,
		Reduction: reductionDigests,
	})
	return err
}

type recoveredState struct {
	CapacityAdmitted     bool
	Reservations         []fuzzcorpus.ResourceIdentity
	Lease                *fuzzcorpus.ResourceIdentity
	CompletedTrials      map[int32]bool
	CleanupStarted       bool
	ReservationsReleased bool
	LeaseReleaseIntended bool
	LeaseReleased        bool
	ReportRetained       bool
	SessionComplete      bool
}

func recoverState(records []fuzzcorpus.JournalRecord) (recoveredState, error) {
	state := recoveredState{CompletedTrials: map[int32]bool{}}
	for _, record := range records {
		switch record.Kind {
		case "SessionLeaseAcquired":
			if len(record.Resources) != 1 {
				return state, errors.New("lease journal record is incomplete")
			}
			lease := record.Resources[0]
			state.Lease = &lease
		case "CapacityAdmitted":
			state.CapacityAdmitted = true
			state.Reservations = append([]fuzzcorpus.ResourceIdentity(nil), record.Resources...)
		case "TrialComplete":
			state.CompletedTrials[record.TrialOrdinal] = true
		case "SessionCleanupStarted":
			state.CleanupStarted = true
		case "ReservationsReleased":
			state.ReservationsReleased = true
		case "IntentReleaseSessionLease":
			state.LeaseReleaseIntended = true
		case "SessionLeaseReleased":
			state.LeaseReleased = true
		case "SessionReportRetained":
			if len(record.Artifacts) != 1 {
				return state, errors.New("session report journal record is incomplete")
			}
			state.ReportRetained = true
		case "SessionComplete":
			state.SessionComplete = true
		}
	}
	return state, nil
}

func (engine *Engine) acquireOrResumeLease(
	ctx context.Context,
	journal *fuzzcorpus.Journal,
	state recoveredState,
	holder string,
) (fuzzcorpus.ResourceIdentity, error) {
	lease, err := engine.Runtime.AcquireSession(ctx, holder)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	if state.Lease != nil && (lease.UID != state.Lease.UID || lease.Name != state.Lease.Name) {
		return fuzzcorpus.ResourceIdentity{}, errors.New("resumed session lease identity changed")
	}
	if state.Lease == nil {
		if _, err := journal.Append(fuzzcorpus.JournalRecord{
			Kind: "SessionLeaseAcquired", Phase: "Planned",
			Resources: []fuzzcorpus.ResourceIdentity{lease},
		}); err != nil {
			return fuzzcorpus.ResourceIdentity{}, err
		}
	}
	return lease, nil
}

func observedIdentities(
	records []fuzzcorpus.JournalRecord, ordinal int32, attempt string,

) ([]fuzzcorpus.ResourceIdentity, []fuzzcorpus.ResourceIdentity, []fuzzcorpus.ResourceIdentity, *fuzzcorpus.ResourceIdentity, *fuzzcorpus.ResourceIdentity) {
	var policies []fuzzcorpus.ResourceIdentity
	var templates []fuzzcorpus.ResourceIdentity
	var evidence []fuzzcorpus.ResourceIdentity
	var network, run *fuzzcorpus.ResourceIdentity
	for _, record := range records {
		if record.TrialOrdinal != ordinal || record.AttemptID != attempt {
			continue
		}
		if record.Kind == "PoliciesObserved" {
			policies = append([]fuzzcorpus.ResourceIdentity(nil), record.Resources...)
			continue
		}
		if record.Kind == "EvidencePlaneObserved" {
			evidence = append([]fuzzcorpus.ResourceIdentity(nil), record.Resources...)
			continue
		}
		if record.Kind == "TemplatesObserved" {
			templates = append([]fuzzcorpus.ResourceIdentity(nil), record.Resources...)
			continue
		}
		if len(record.Resources) != 1 {
			continue
		}
		copy := record.Resources[0]
		switch record.Kind {
		case "NetworkObserved":
			network = &copy
		case "RunObserved":
			run = &copy
		}
	}
	return policies, templates, evidence, network, run
}

func attemptResources(attempt ObservedAttempt) []fuzzcorpus.ResourceIdentity {
	resources := append([]fuzzcorpus.ResourceIdentity(nil), attempt.Policies...)
	resources = append(resources, attempt.Templates...)
	resources = append(resources, attempt.EvidencePlane...)
	return append(resources, attempt.Network, attempt.Run)
}

func bindTemplateIdentities(
	materialized *fuzzplan.MaterializedTrial,
	identities []fuzzcorpus.ResourceIdentity,
) error {
	if materialized == nil || len(identities) != len(materialized.FaultTemplates)+len(materialized.UpgradeTemplates) {
		return errors.New("materialized template identity inventory is incomplete")
	}
	byKindAndName := make(map[string]fuzzcorpus.ResourceIdentity, len(identities))
	for _, identity := range identities {
		if identity.UID == "" || identity.Generation < 1 {
			return errors.New("materialized template has no immutable API identity")
		}
		key := identity.Kind + "/" + identity.Name
		if _, duplicate := byKindAndName[key]; duplicate {
			return errors.New("materialized template identity is duplicated")
		}
		byKindAndName[key] = identity
	}
	for index := range materialized.Run.Spec.CampaignCatalog {
		catalog := &materialized.Run.Spec.CampaignCatalog[index]
		identity, found := byKindAndName["FaultCampaign/"+catalog.CampaignRef]
		if !found {
			return fmt.Errorf("fault template %s has no observed identity", catalog.CampaignRef)
		}
		generation := identity.Generation
		catalog.ExpectedUID = identity.UID
		catalog.ExpectedGeneration = &generation
	}
	for index := range materialized.Run.Spec.UpgradeCatalog {
		catalog := &materialized.Run.Spec.UpgradeCatalog[index]
		identity, found := byKindAndName["UpgradeCampaign/"+catalog.UpgradeRef]
		if !found {
			return fmt.Errorf("upgrade template %s has no observed identity", catalog.UpgradeRef)
		}
		generation := identity.Generation
		catalog.ExpectedUID = identity.UID
		catalog.ExpectedGeneration = &generation
	}
	return nil
}

func sameResourceIdentities(left, right []fuzzcorpus.ResourceIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (engine *Engine) harnessFailed(
	journal *fuzzcorpus.Journal, reason string, cause error,
) error {
	_, appendErr := journal.Append(fuzzcorpus.JournalRecord{
		Kind: reason, Phase: "HarnessFailed",
	})
	if appendErr != nil {
		return errors.Join(cause, appendErr)
	}
	return fmt.Errorf("%s: %w", reason, cause)
}
