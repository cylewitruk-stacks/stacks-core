package fuzzsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

type fakeRuntime struct {
	leaseMu                sync.Mutex
	lease                  fuzzcorpus.ResourceIdentity
	releasedLease          fuzzcorpus.ResourceIdentity
	renewCalls             int
	renewFailsAt           int
	renewTransientFailures int
	policies               map[string]fuzzcorpus.ResourceIdentity
	templates              map[string]fuzzcorpus.ResourceIdentity
	networks               map[string]fuzzcorpus.ResourceIdentity
	runs                   map[string]fuzzcorpus.ResourceIdentity
	captureFails           int
	teardowns              int
	reductionTeardownFails int
	failure                bool
	waitFailsAt            int
	waitCalls              int
	readyCalls             int
	leaseReleaseFails      int
	leaseGone              bool
	captureLimits          []int64
	artifactSize           int
	evidencePlanes         map[string][]fuzzcorpus.ResourceIdentity
	evidenceReleases       int
	capacityCalls          int
	reservationReleases    [][]fuzzcorpus.ResourceIdentity
	reserveHook            func()
	waitDelay              time.Duration
	blockWait              bool
}

func (runtime *fakeRuntime) AcquireSession(_ context.Context, _ string) (fuzzcorpus.ResourceIdentity, error) {
	runtime.leaseMu.Lock()
	defer runtime.leaseMu.Unlock()
	if runtime.lease.UID == "" {
		runtime.lease = testIdentity("Lease", "attacknet-fuzz-session", "lease-uid")
	}
	return runtime.lease, nil
}
func (runtime *fakeRuntime) RenewSession(_ context.Context, lease fuzzcorpus.ResourceIdentity, _ string) (fuzzcorpus.ResourceIdentity, error) {
	runtime.leaseMu.Lock()
	defer runtime.leaseMu.Unlock()
	if lease.UID != runtime.lease.UID {
		return fuzzcorpus.ResourceIdentity{}, errors.New("lease changed")
	}
	runtime.renewCalls++
	if runtime.renewTransientFailures > 0 {
		runtime.renewTransientFailures--
		return fuzzcorpus.ResourceIdentity{}, errors.New("injected transient lease renewal failure")
	}
	if runtime.renewFailsAt > 0 && runtime.renewCalls >= runtime.renewFailsAt {
		return fuzzcorpus.ResourceIdentity{}, fmt.Errorf("%w: injected lease renewal loss", errLeaseOwnershipLost)
	}
	runtime.lease.ResourceVersion = strconv.Itoa(runtime.renewCalls + 1)
	return runtime.lease, nil
}
func (runtime *fakeRuntime) ReleaseSession(_ context.Context, lease fuzzcorpus.ResourceIdentity, _ string) error {
	runtime.leaseMu.Lock()
	defer runtime.leaseMu.Unlock()
	runtime.releasedLease = lease
	if runtime.leaseReleaseFails > 0 {
		runtime.leaseReleaseFails--
		runtime.leaseGone = true
		return errors.New("injected post-delete lease interruption")
	}
	if runtime.leaseGone {
		return nil
	}
	runtime.leaseGone = true
	return nil
}
func (runtime *fakeRuntime) Capacity(context.Context, fuzzplan.Descriptor) (CapacitySnapshot, error) {
	runtime.capacityCalls++
	return CapacitySnapshot{
		Nodes:                []NodeCapacity{{Name: "worker", RootAvailableBytes: 1 << 30, ImageAvailableBytes: 1 << 30}},
		CorpusAvailableBytes: 1 << 30,
	}, nil
}
func (runtime *fakeRuntime) Reserve(context.Context, fuzzplan.Descriptor) ([]fuzzcorpus.ResourceIdentity, error) {
	if runtime.reserveHook != nil {
		runtime.reserveHook()
	}
	return []fuzzcorpus.ResourceIdentity{testIdentity("PersistentVolumeClaim", "escrow", "escrow-uid")}, nil
}
func (runtime *fakeRuntime) ReleaseReservation(_ context.Context, resources []fuzzcorpus.ResourceIdentity) error {
	runtime.reservationReleases = append(
		runtime.reservationReleases,
		append([]fuzzcorpus.ResourceIdentity(nil), resources...),
	)
	return nil
}
func (runtime *fakeRuntime) EnsurePolicy(_ context.Context, desired *attacknetv1beta1.BurnchainPolicy, expected *fuzzcorpus.ResourceIdentity, _ bool) (fuzzcorpus.ResourceIdentity, error) {
	if runtime.policies == nil {
		runtime.policies = map[string]fuzzcorpus.ResourceIdentity{}
	}
	if current, found := runtime.policies[desired.Name]; found {
		if expected == nil || expected.UID != current.UID || expected.Generation != current.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("policy identity mismatch")
		}
		return current, nil
	}
	if expected != nil {
		return fuzzcorpus.ResourceIdentity{}, errors.New("policy vanished")
	}
	identity := testIdentity("BurnchainPolicy", desired.Name, "policy-"+desired.Name)
	runtime.policies[desired.Name] = identity
	return identity, nil
}
func (runtime *fakeRuntime) EnsureTemplates(
	_ context.Context,
	faults []attacknetv1beta1.FaultCampaign,
	upgrades []attacknetv1beta1.UpgradeCampaign,
	expected []fuzzcorpus.ResourceIdentity,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if runtime.templates == nil {
		runtime.templates = map[string]fuzzcorpus.ResourceIdentity{}
	}
	if expected != nil && len(expected) != len(faults)+len(upgrades) {
		return nil, errors.New("template identity count mismatch")
	}
	expectedByKey := map[string]fuzzcorpus.ResourceIdentity{}
	for _, identity := range expected {
		expectedByKey[identity.Kind+"/"+identity.Name] = identity
	}
	result := make([]fuzzcorpus.ResourceIdentity, 0, len(faults)+len(upgrades))
	ensure := func(kind, name string) error {
		key := kind + "/" + name
		if current, found := runtime.templates[key]; found {
			if wanted, present := expectedByKey[key]; !present || wanted.UID != current.UID ||
				wanted.Generation != current.Generation {
				return errors.New("template identity mismatch")
			}
			result = append(result, current)
			return nil
		}
		if expected != nil {
			return errors.New("template vanished")
		}
		identity := testIdentity(kind, name, "template-"+name)
		runtime.templates[key] = identity
		result = append(result, identity)
		return nil
	}
	for _, template := range faults {
		if err := ensure("FaultCampaign", template.Name); err != nil {
			return nil, err
		}
	}
	for _, template := range upgrades {
		if err := ensure("UpgradeCampaign", template.Name); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func (runtime *fakeRuntime) EnsureNetwork(_ context.Context, desired *attacknetv1beta1.StacksNetwork, expected *fuzzcorpus.ResourceIdentity) (fuzzcorpus.ResourceIdentity, error) {
	if runtime.networks == nil {
		runtime.networks = map[string]fuzzcorpus.ResourceIdentity{}
	}
	if current, found := runtime.networks[desired.Name]; found {
		if expected == nil || expected.UID != current.UID || expected.Generation != current.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("network identity mismatch")
		}
		return current, nil
	}
	if expected != nil {
		return fuzzcorpus.ResourceIdentity{}, errors.New("network vanished")
	}
	identity := testIdentity("StacksNetwork", desired.Name, "network-"+desired.Name)
	runtime.networks[desired.Name] = identity
	return identity, nil
}
func (runtime *fakeRuntime) WaitNetworkReady(context.Context, fuzzcorpus.ResourceIdentity) error {
	runtime.readyCalls++
	return nil
}
func (runtime *fakeRuntime) EnsureEvidencePlane(
	_ context.Context, network fuzzcorpus.ResourceIdentity, expected []fuzzcorpus.ResourceIdentity,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if runtime.evidencePlanes == nil {
		runtime.evidencePlanes = map[string][]fuzzcorpus.ResourceIdentity{}
	}
	if current, found := runtime.evidencePlanes[network.UID]; found {
		if !sameResourceIdentities(current, expected) {
			return nil, errors.New("evidence-plane identity mismatch")
		}
		return append([]fuzzcorpus.ResourceIdentity(nil), current...), nil
	}
	if expected != nil {
		return nil, errors.New("evidence plane vanished")
	}
	resources := []fuzzcorpus.ResourceIdentity{
		testIdentity("ConfigMap", network.Name+"-evidence", "evidence-"+network.UID),
	}
	runtime.evidencePlanes[network.UID] = resources
	return append([]fuzzcorpus.ResourceIdentity(nil), resources...), nil
}
func (runtime *fakeRuntime) ReleaseEvidencePlane(
	_ context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	if len(resources) == 0 {
		return errors.New("evidence-plane identities are required")
	}
	for networkUID, current := range runtime.evidencePlanes {
		if sameResourceIdentities(current, resources) {
			delete(runtime.evidencePlanes, networkUID)
			runtime.evidenceReleases++
			return nil
		}
	}
	// Release is idempotent after a journaled exact deletion.
	return nil
}
func (runtime *fakeRuntime) EnsureRun(_ context.Context, desired *attacknetv1beta1.AttacknetRun, expected *fuzzcorpus.ResourceIdentity) (fuzzcorpus.ResourceIdentity, error) {
	for _, catalog := range desired.Spec.CampaignCatalog {
		identity, found := runtime.templates["FaultCampaign/"+catalog.CampaignRef]
		if !found || catalog.ExpectedUID != identity.UID || catalog.ExpectedGeneration == nil ||
			*catalog.ExpectedGeneration != identity.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("run does not bind its materialized fault template")
		}
	}
	for _, catalog := range desired.Spec.UpgradeCatalog {
		identity, found := runtime.templates["UpgradeCampaign/"+catalog.UpgradeRef]
		if !found || catalog.ExpectedUID != identity.UID || catalog.ExpectedGeneration == nil ||
			*catalog.ExpectedGeneration != identity.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("run does not bind its materialized upgrade template")
		}
	}
	if runtime.runs == nil {
		runtime.runs = map[string]fuzzcorpus.ResourceIdentity{}
	}
	if current, found := runtime.runs[desired.Name]; found {
		if expected == nil || expected.UID != current.UID || expected.Generation != current.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("run identity mismatch")
		}
		return current, nil
	}
	if expected != nil {
		return fuzzcorpus.ResourceIdentity{}, errors.New("run vanished")
	}
	identity := testIdentity("AttacknetRun", desired.Name, "run-"+desired.Name)
	runtime.runs[desired.Name] = identity
	return identity, nil
}
func (runtime *fakeRuntime) WaitRunTerminal(ctx context.Context, run fuzzcorpus.ResourceIdentity) (ObservedAttempt, error) {
	runtime.waitCalls++
	if runtime.blockWait {
		<-ctx.Done()
		return ObservedAttempt{}, ctx.Err()
	}
	if runtime.waitDelay > 0 {
		timer := time.NewTimer(runtime.waitDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ObservedAttempt{}, ctx.Err()
		case <-timer.C:
		}
	}
	if runtime.waitFailsAt != 0 && runtime.waitCalls == runtime.waitFailsAt {
		return ObservedAttempt{}, errors.New("injected terminal observation interruption")
	}
	result := TrialResult{
		Phase: "Passed", Reason: "AllRecovered", Attribution: "ProtocolAssertion",
		EvidenceComplete: true, IncidentBundleSealed: true, LokiExportComplete: true,
	}
	if runtime.failure {
		result.Phase = "Failed"
		result.Reason = "ProtocolRecoveryViolated"
		result.ViolatedAssertions = []string{"recovery/chain-progress:Violated"}
		result.MechanismFamilies = []string{"network"}
	}
	return ObservedAttempt{
		Run: run, ScheduleDigest: "sha256:" + strings.Repeat("d", 64),
		Result: result,
	}, nil
}

func TestReductionResumeRestoresOutcomesAndReusesExactResources(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{failure: true, waitFailsAt: 4}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("injected reduction interruption did not stop the session")
	}
	policyCount, networkCount, runCount := len(runtime.policies), len(runtime.networks), len(runtime.runs)
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	if len(runtime.policies) < policyCount || len(runtime.networks) < networkCount || len(runtime.runs) < runCount {
		t.Fatal("resume lost previously journaled resource identities")
	}
	entries, err := store.Entries()
	if err != nil || len(entries) != 1 || len(entries[0].Reduction) != 1 {
		t.Fatalf("resumed reduction did not seal one corpus entry: %#v, %v", entries, err)
	}
}

func TestSessionLeaseHeartbeatRenewsAndReleasesLatestIdentity(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{waitDelay: 30 * time.Millisecond}
	engine := Engine{
		Runtime: runtime, Store: store, LeaseRenewInterval: 5 * time.Millisecond,
	}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	runtime.leaseMu.Lock()
	defer runtime.leaseMu.Unlock()
	if runtime.renewCalls < 2 {
		t.Fatalf("lease renewals = %d, want at least 2", runtime.renewCalls)
	}
	if runtime.releasedLease.ResourceVersion != runtime.lease.ResourceVersion {
		t.Fatalf("released stale lease identity: %#v != %#v", runtime.releasedLease, runtime.lease)
	}
}

func TestSessionLeaseHeartbeatRetriesTransientRenewalFailure(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{waitDelay: 30 * time.Millisecond, renewTransientFailures: 2}
	engine := Engine{
		Runtime: runtime, Store: store, LeaseRenewInterval: 5 * time.Millisecond,
		LeaseRenewDeadline: 20 * time.Millisecond, LeaseRetryInterval: time.Millisecond,
	}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	runtime.leaseMu.Lock()
	defer runtime.leaseMu.Unlock()
	if runtime.renewCalls < 3 {
		t.Fatalf("lease renewal calls = %d, want transient retries plus success", runtime.renewCalls)
	}
}

func TestSessionLeaseHeartbeatCancelsWorkOnOwnershipLoss(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{blockWait: true, renewFailsAt: 3}
	engine := Engine{
		Runtime: runtime, Store: store, LeaseRenewInterval: 5 * time.Millisecond,
	}
	started := time.Now()
	err = engine.Run(context.Background(), descriptor)
	if err == nil || !strings.Contains(err.Error(), "SessionLeaseLost") {
		t.Fatalf("lease loss did not fail closed: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("lease loss did not cancel active work promptly")
	}
	runtime.leaseMu.Lock()
	renewCalls := runtime.renewCalls
	runtime.leaseMu.Unlock()
	if renewCalls != 3 {
		t.Fatalf("renewal calls = %d, want 3", renewCalls)
	}
}

func TestSessionWallTimeDoesNotResetOnResume(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{captureFails: 1}
	engine := Engine{
		Runtime: runtime, Store: store, Now: clock.Now, LeaseRenewInterval: time.Hour,
	}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("injected interruption did not leave a resumable session")
	}
	waits := runtime.waitCalls
	clock.Advance(2 * time.Hour)
	err = engine.Run(context.Background(), descriptor)
	if err == nil || !strings.Contains(err.Error(), "SessionPlanned wall-time budget is exhausted") {
		t.Fatalf("expired resumed session = %v", err)
	}
	if runtime.waitCalls != waits {
		t.Fatal("expired resumed session performed new runtime work")
	}
}

func TestReductionWallTimeDoesNotResetOnResume(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{failure: true, reductionTeardownFails: 1}
	engine := Engine{
		Runtime: runtime, Store: store, Now: clock.Now, LeaseRenewInterval: time.Hour,
	}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("injected reduction interruption did not stop the session")
	}
	clock.Advance(2 * time.Minute)
	err = engine.Run(context.Background(), descriptor)
	if err == nil || !strings.Contains(err.Error(), "ReductionStarted wall-time budget is exhausted") {
		t.Fatalf("expired resumed reduction = %v", err)
	}
	journal, journalErr := store.OpenJournal(descriptor.Digest)
	if journalErr != nil {
		t.Fatal(journalErr)
	}
	if !hasAttemptRecord(journal.Records(), "AttemptTeardownComplete", 1, "reduce-001") {
		t.Fatal("expired reduction did not reconcile its captured environment")
	}
}

func TestReductionResumeCleansCapturedAttemptBeforeAdvancing(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{failure: true, reductionTeardownFails: 1}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("injected post-outcome teardown interruption did not stop the session")
	}
	journal, err := store.OpenJournal(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttemptRecord(journal.Records(), "ReductionOutcomeRecorded", 1, "reduce-001") ||
		hasAttemptRecord(journal.Records(), "AttemptTeardownComplete", 1, "reduce-001") {
		t.Fatal("fixture did not stop between reduction outcome and teardown completion")
	}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	journal, err = store.OpenJournal(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttemptRecord(journal.Records(), "AttemptTeardownComplete", 1, "reduce-001") {
		t.Fatal("resume advanced without reconciling the captured reduction attempt")
	}
}

func TestSessionCleanupResumesAfterLeaseWasDeleted(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{leaseReleaseFails: 1}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("post-delete interruption did not stop before completion record")
	}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	journal, err := store.OpenJournal(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	records := journal.Records()
	if records[len(records)-1].Kind != "SessionComplete" {
		t.Fatalf("cleanup resume did not close session: %#v", records[len(records)-1])
	}
}

func TestEngineConfirmsAndReducesOnFreshNetworks(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{failure: true}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Classification != "ConfirmedNetworkFailure" ||
		len(entries[0].Attempts) < 3 || len(entries[0].Reduction) != 1 {
		t.Fatalf("confirmed failure did not retain fresh replay and reduction: %#v", entries)
	}
	if runtime.teardowns != len(entries[0].Attempts) {
		t.Fatalf("fresh attempt teardown count = %d, want %d", runtime.teardowns, len(entries[0].Attempts))
	}
}

func TestExecuteCorpusUsesFreshAttemptAndResumesCompletedRequest(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(descriptor.Corpus.Root, descriptor.Corpus.MaximumBytes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Engine{Runtime: &fakeRuntime{failure: true}, Store: store}).Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("source corpus entries = %#v, %v", entries, err)
	}
	var descriptorReference *fuzzcorpus.ObjectReference
	for index := range entries[0].Objects {
		if entries[0].Objects[index].Name == "session-descriptor" {
			descriptorReference = &entries[0].Objects[index]
			break
		}
	}
	if descriptorReference == nil {
		t.Fatal("corpus entry did not retain its session descriptor")
	}
	retainedBytes, err := store.ReadObject(*descriptorReference)
	if err != nil {
		t.Fatal(err)
	}
	var retainedDescriptor fuzzplan.Descriptor
	if err := json.Unmarshal(retainedBytes, &retainedDescriptor); err != nil {
		t.Fatal(err)
	}
	// A new runtime represents a fresh cluster after the planning-namespace
	// source templates were deleted. Replay must create only the portable specs
	// retained in the corpus descriptor.
	runtime := &fakeRuntime{failure: true, waitDelay: 30 * time.Millisecond}
	engine := &Engine{
		Runtime: runtime, Store: store, LeaseRenewInterval: 5 * time.Millisecond,
	}
	result, err := engine.ExecuteCorpus(context.Background(), retainedDescriptor, entries[0], "manual-replay", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.templates) == 0 {
		t.Fatal("corpus replay did not materialize its retained template")
	}
	for key := range runtime.templates {
		if strings.HasSuffix(key, "/fault-template") {
			t.Fatalf("corpus replay referenced deleted source template: %s", key)
		}
	}
	if result.Classification != "ConfirmedNetworkFailure" || !result.Reduced || result.RequestDigest == "" {
		t.Fatalf("explicit corpus execution = %#v", result)
	}
	runtime.leaseMu.Lock()
	renewCalls := runtime.renewCalls
	runtime.leaseMu.Unlock()
	if renewCalls < 2 {
		t.Fatalf("corpus execution lease renewals = %d, want at least 2", renewCalls)
	}
	waits := runtime.waitCalls
	resumed, err := engine.ExecuteCorpus(context.Background(), retainedDescriptor, entries[0], "manual-replay", true)
	if err != nil {
		t.Fatal(err)
	}
	if resumed != result || runtime.waitCalls != waits {
		t.Fatalf("completed corpus request was re-executed: %#v != %#v, waits %d != %d", resumed, result, runtime.waitCalls, waits)
	}
}

func (runtime *fakeRuntime) SuspendNetwork(context.Context, fuzzcorpus.ResourceIdentity) error {
	return nil
}
func (runtime *fakeRuntime) Capture(_ context.Context, attempt ObservedAttempt, maximumBytes int64) (ObservedAttempt, error) {
	runtime.captureLimits = append(runtime.captureLimits, maximumBytes)
	if runtime.captureFails > 0 {
		runtime.captureFails--
		return ObservedAttempt{}, errors.New("injected capture interruption")
	}
	data := []byte("{\"complete\":true}")
	if runtime.artifactSize > 0 {
		data = make([]byte, runtime.artifactSize)
	}
	attempt.Artifacts = []Artifact{{
		Name: "evidence-manifest", ContentType: "application/json",
		Data: data,
	}}
	return attempt, nil
}

func TestReductionEvidenceBudgetStopsBeforeAnUnboundedAttempt(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(descriptor.Corpus.Root, descriptor.Corpus.MaximumBytes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture has a 16MiB aggregate bound. A 13MiB first reduction leaves
	// less than the 4MiB minimum required for another complete capture.
	runtime := &fakeRuntime{failure: true, artifactSize: 13 << 20}
	if err := (&Engine{Runtime: runtime, Store: store}).Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Entries()
	if err != nil || len(entries) != 1 || len(entries[0].Attempts) != 3 {
		t.Fatalf("evidence-bounded attempts = %#v, %v", entries, err)
	}
	if got := runtime.captureLimits[len(runtime.captureLimits)-1]; got != 16<<20 {
		t.Fatalf("reduction capture limit = %d", got)
	}
}
func (runtime *fakeRuntime) Teardown(_ context.Context, attempt ObservedAttempt) error {
	runtime.teardowns++
	if attempt.AttemptKind == "Reduction" && runtime.reductionTeardownFails > 0 {
		runtime.reductionTeardownFails--
		return errors.New("injected reduction teardown interruption")
	}
	return nil
}

func TestEngineRunsFiniteSessionAndStoresReplayableEntry(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Classification != "Clean" ||
		len(entries[0].Attempts) != 1 || runtime.teardowns != 1 || runtime.readyCalls != 2 ||
		runtime.capacityCalls != 3 {
		t.Fatalf("finite session did not persist and teardown exactly once: %#v", entries)
	}
	pointer, err := store.Report(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadObject(pointer.Report)
	if err != nil || !strings.Contains(string(data), `"status":"Complete"`) ||
		!strings.Contains(string(data), entries[0].Digest) {
		t.Fatalf("session report is incomplete: %s, %v", data, err)
	}
}

func TestEngineResumeReusesExactResourceIdentities(t *testing.T) {
	descriptor := engineDescriptor(t)
	store, err := fuzzcorpus.Open(t.TempDir(), 1<<30, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{captureFails: 1}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("injected interruption did not stop the session")
	}
	policyCount, networkCount, runCount := len(runtime.policies), len(runtime.networks), len(runtime.runs)
	if err := engine.Run(context.Background(), descriptor); err != nil {
		t.Fatal(err)
	}
	if len(runtime.policies) != policyCount || len(runtime.networks) != networkCount || len(runtime.runs) != runCount {
		t.Fatal("resume duplicated Kubernetes resources")
	}
}

func TestCapacityAdmissionRollsBackReservationWhenJournalWriteFails(t *testing.T) {
	descriptor := engineDescriptor(t)
	root := t.TempDir()
	const maximumBytes = int64(64 << 10)
	store, err := fuzzcorpus.Open(root, maximumBytes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{reserveHook: func() {
		// Model a physical escrow created after the last successful corpus
		// write. The next journal append must discover the exhausted bound.
		if err := os.WriteFile(root+"/.capacity-escrow-test", make([]byte, maximumBytes), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	engine := Engine{Runtime: runtime, Store: store}
	if err := engine.Run(context.Background(), descriptor); err == nil {
		t.Fatal("capacity journal exhaustion did not stop the session")
	}
	if len(runtime.reservationReleases) != 1 ||
		len(runtime.reservationReleases[0]) != 1 ||
		runtime.reservationReleases[0][0].UID != "escrow-uid" {
		t.Fatalf("unjournaled reservation was not rolled back: %#v", runtime.reservationReleases)
	}
}

func engineDescriptor(t *testing.T) fuzzplan.Descriptor {
	t.Helper()
	plan := fuzzplan.Plan{
		SchemaVersion: fuzzplan.PlanSchema, SessionID: "session", Seed: "seed",
		MaxTrials: 1, MaxDuration: metav1.Duration{Duration: time.Hour},
		Network: fuzzplan.NetworkPlan{TemplateFile: "network.yaml"},
		Templates: []fuzzplan.TemplatePlan{{
			ID: "fault", Kind: "FaultCampaign", Name: "fault-template",
			Weight: 1, MaxUses: 1, ExpectedUID: "template-uid",
		}},
		Generation: fuzzplan.GenerationPlan{
			MinExecutions: 1, MaxExecutions: 1,
			Triggers: []attacknetv1beta1.RunTriggerSpec{{}},
		},
		Run: fuzzplan.RunPlan{
			Budgets: attacknetv1beta1.RunBudgets{
				MaxCampaigns: 1, MaxWallTimeSeconds: 60,
				MaxCumulativeFaultSeconds: 30, MaxActiveFaults: 1,
				MaxSignerImpactPercent: 100, MaxBurnchainFaults: 1,
				MaxInconclusiveCampaigns: 1,
			},
			StopPolicy: attacknetv1beta1.StopPolicy{
				OnCampaignFailure: "Stop", OnInconclusive: "Stop",
				OnBudgetExhausted: "Stop", OnSuccess: "Continue",
			},
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{
				RequiredOnFailure: true, RequireIncidentBundle: true,
				AllowedTerminalStates: []string{"Triaged", "Remediated", "Inconclusive"},
			},
		},
		Confirmation: fuzzplan.ConfirmationPlan{RequiredMatches: 1, MaxAttempts: 1},
		Reduction: fuzzplan.ReductionPlan{
			Enabled: true, MaxAttempts: 4,
			MaxDuration: metav1.Duration{Duration: time.Minute}, MaxEvidenceBytes: 16 << 20,
		},
		Capacity: fuzzplan.CapacityPlan{
			MinimumNodeBytes: 1, MinimumImageBytes: 1, MinimumCorpusBytes: 1,
		},
		Corpus: fuzzplan.CorpusPlan{Root: t.TempDir(), MaximumBytes: 1 << 30},
	}
	planDigest, err := fuzzplan.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	network := attacknetv1beta1.StacksNetwork{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "template", Namespace: "test"},
		Spec: attacknetv1beta1.StacksNetworkSpec{Burnchain: attacknetv1beta1.BurnchainTopologySpec{
			PolicyRef: attacknetv1beta1.NamedObjectReference{Name: "template-clock"},
			Nodes:     []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin"}},
		}},
	}
	networkDigest, err := fuzzplan.NetworkTemplateDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	faultSpec := attacknetv1beta1.FaultCampaignSpec{Template: true, Stages: []attacknetv1beta1.FaultStageSpec{
		{ID: "first", Faults: []attacknetv1beta1.FaultActionSpec{{ID: "a", Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner", "follower"}}}}},
		{ID: "second", Faults: []attacknetv1beta1.FaultActionSpec{{ID: "b", Target: attacknetv1beta1.FaultTarget{Actors: []string{"signer", "follower"}}}}},
	}}
	faultDigest, err := canonical.ArtifactDigest(faultSpec)
	if err != nil {
		t.Fatal(err)
	}
	policySpec := attacknetv1beta1.BurnchainPolicySpec{NetworkRef: "template", BitcoinNodeRef: "bitcoin"}
	policyDigest, err := canonical.ArtifactDigest(policySpec)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := fuzzplan.Compile(fuzzplan.ResolvedInput{
		Plan: plan, PlanDigest: planDigest,
		Network: fuzzplan.ResolvedNetwork{TemplateDigest: networkDigest, Template: network, Policies: []fuzzplan.ResolvedPolicy{{
			Name: "template-clock", Namespace: "test", UID: "policy-template-clock",
			Generation: 1, SpecDigest: policyDigest, Spec: policySpec,
		}}},
		Templates: []fuzzplan.ResolvedTemplate{{
			ID: "fault", Kind: "FaultCampaign", Name: "fault-template",
			Namespace: "test", UID: "template-uid", Generation: 1,
			SpecDigest: faultDigest, Weight: 1, MaxUses: 1, FaultSpec: &faultSpec,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func testIdentity(kind, name, uid string) fuzzcorpus.ResourceIdentity {
	return fuzzcorpus.ResourceIdentity{
		APIVersion: "v1", Kind: kind, Namespace: "test", Name: name,
		UID: uid, ResourceVersion: "1",
		Generation: 1,
	}
}

type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.current
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.current = clock.current.Add(duration)
}
