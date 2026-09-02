package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

// FuzzInfrastructure owns the narrowly scoped Lease and capacity resources.
type FuzzInfrastructure interface {
	AcquireSession(context.Context, string) (fuzzcorpus.ResourceIdentity, error)
	RenewSession(context.Context, fuzzcorpus.ResourceIdentity, string) (fuzzcorpus.ResourceIdentity, error)
	ReleaseSession(context.Context, fuzzcorpus.ResourceIdentity, string) error
	Capacity(context.Context, fuzzplan.Descriptor) (fuzzsession.CapacitySnapshot, error)
	Reserve(context.Context, fuzzplan.Descriptor) ([]fuzzcorpus.ResourceIdentity, error)
	ReleaseReservation(context.Context, []fuzzcorpus.ResourceIdentity) error
}

// FuzzEvidencePlane owns the per-attempt telemetry resources required for
// complete incident and retained-log capture.
type FuzzEvidencePlane interface {
	Ensure(context.Context, fuzzcorpus.ResourceIdentity, []fuzzcorpus.ResourceIdentity) ([]fuzzcorpus.ResourceIdentity, error)
	Release(context.Context, []fuzzcorpus.ResourceIdentity) error
}

type fuzzInfrastructureAdmin interface {
	SessionLease(context.Context) (fuzzcorpus.ResourceIdentity, string, error)
	BreakSession(context.Context, fuzzcorpus.ResourceIdentity, string, string) error
}

// FuzzLeaseAdmin is the explicit, audited stale-session recovery boundary.
type FuzzLeaseAdmin interface {
	SessionLease(context.Context) (fuzzcorpus.ResourceIdentity, string, error)
	BreakSession(context.Context, fuzzcorpus.ResourceIdentity, string, string) error
}

// KubernetesFuzzRuntime adapts the existing typed CLI evidence and teardown
// boundaries to the generic resumable session engine.
type KubernetesFuzzRuntime struct {
	Backend        Backend
	Infrastructure FuzzInfrastructure
	EvidencePlane  FuzzEvidencePlane
	Incident       IncidentEvidenceReader
	Logs           RetainedLogExporter
	CorpusRoot     string
	Now            func() time.Time
}

func (runtimeBoundary *KubernetesFuzzRuntime) AcquireSession(ctx context.Context, holder string) (fuzzcorpus.ResourceIdentity, error) {
	return runtimeBoundary.Infrastructure.AcquireSession(ctx, holder)
}
func (runtimeBoundary *KubernetesFuzzRuntime) RenewSession(ctx context.Context, lease fuzzcorpus.ResourceIdentity, holder string) (fuzzcorpus.ResourceIdentity, error) {
	return runtimeBoundary.Infrastructure.RenewSession(ctx, lease, holder)
}
func (runtimeBoundary *KubernetesFuzzRuntime) ReleaseSession(ctx context.Context, lease fuzzcorpus.ResourceIdentity, holder string) error {
	return runtimeBoundary.Infrastructure.ReleaseSession(ctx, lease, holder)
}

// SessionLease inspects the exact current session Lease without mutation.
func (runtimeBoundary *KubernetesFuzzRuntime) SessionLease(
	ctx context.Context,
) (fuzzcorpus.ResourceIdentity, string, error) {
	admin, ok := runtimeBoundary.Infrastructure.(fuzzInfrastructureAdmin)
	if !ok {
		return fuzzcorpus.ResourceIdentity{}, "", errors.New("fuzz infrastructure does not support Lease administration")
	}
	return admin.SessionLease(ctx)
}

// BreakSession records an immutable intent and completion receipt around one
// exact stale-Lease deletion. It never discovers or substitutes identity.
func (runtimeBoundary *KubernetesFuzzRuntime) BreakSession(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity, holder, reason string,
) error {
	admin, ok := runtimeBoundary.Infrastructure.(fuzzInfrastructureAdmin)
	if !ok {
		return errors.New("fuzz infrastructure does not support Lease administration")
	}
	store, err := fuzzcorpus.OpenExisting(runtimeBoundary.CorpusRoot, runtimeBoundary.Now)
	if err != nil {
		return err
	}
	receipt := struct {
		SchemaVersion string                      `json:"schemaVersion"`
		Phase         string                      `json:"phase"`
		Lease         fuzzcorpus.ResourceIdentity `json:"lease"`
		Holder        string                      `json:"holder"`
		Reason        string                      `json:"reason"`
		ObservedAt    time.Time                   `json:"observedAt"`
	}{"stacks-attacknet-session-lease-break/v1", "Intent", identity, holder, reason, runtimeBoundary.Now().UTC()}
	if _, err := store.PutAudit("session-lease-break-intent", receipt); err != nil {
		return err
	}
	if err := admin.BreakSession(ctx, identity, holder, reason); err != nil {
		return err
	}
	receipt.Phase = "Complete"
	receipt.ObservedAt = runtimeBoundary.Now().UTC()
	_, err = store.PutAudit("session-lease-break-complete", receipt)
	return err
}
func (runtimeBoundary *KubernetesFuzzRuntime) Capacity(ctx context.Context, descriptor fuzzplan.Descriptor) (fuzzsession.CapacitySnapshot, error) {
	return runtimeBoundary.Infrastructure.Capacity(ctx, descriptor)
}
func (runtimeBoundary *KubernetesFuzzRuntime) Reserve(ctx context.Context, descriptor fuzzplan.Descriptor) ([]fuzzcorpus.ResourceIdentity, error) {
	return runtimeBoundary.Infrastructure.Reserve(ctx, descriptor)
}
func (runtimeBoundary *KubernetesFuzzRuntime) ReleaseReservation(ctx context.Context, resources []fuzzcorpus.ResourceIdentity) error {
	return runtimeBoundary.Infrastructure.ReleaseReservation(ctx, resources)
}

// EnsureEvidencePlane creates or resumes the exact per-attempt telemetry
// resources before a fault run is admitted.
func (runtimeBoundary *KubernetesFuzzRuntime) EnsureEvidencePlane(
	ctx context.Context,
	network fuzzcorpus.ResourceIdentity,
	expected []fuzzcorpus.ResourceIdentity,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if runtimeBoundary.EvidencePlane == nil {
		return nil, errors.New("fuzz evidence-plane provisioner is required")
	}
	return runtimeBoundary.EvidencePlane.Ensure(ctx, network, expected)
}

// ReleaseEvidencePlane removes only the exact journaled telemetry resources.
func (runtimeBoundary *KubernetesFuzzRuntime) ReleaseEvidencePlane(
	ctx context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	if runtimeBoundary.EvidencePlane == nil {
		return errors.New("fuzz evidence-plane provisioner is required")
	}
	return runtimeBoundary.EvidencePlane.Release(ctx, resources)
}

func (runtimeBoundary *KubernetesFuzzRuntime) EnsureNetwork(
	ctx context.Context,
	desired *attacknetv1beta1.StacksNetwork,
	expected *fuzzcorpus.ResourceIdentity,
) (fuzzcorpus.ResourceIdentity, error) {
	return runtimeBoundary.ensureResource(ctx, desired, expected, "StacksNetwork")
}

func (runtimeBoundary *KubernetesFuzzRuntime) EnsurePolicy(
	ctx context.Context,
	desired *attacknetv1beta1.BurnchainPolicy,
	expected *fuzzcorpus.ResourceIdentity,
	allowPausedTransition bool,
) (fuzzcorpus.ResourceIdentity, error) {
	if expected == nil {
		return runtimeBoundary.ensureResource(ctx, desired, nil, "BurnchainPolicy")
	}
	if allowPausedTransition {
		return runtimeBoundary.waitForRestoredPolicy(ctx, desired, *expected)
	}
	kind, _ := LookupKind("BurnchainPolicy")
	current, err := runtimeBoundary.Backend.Get(ctx, ResourceRef{
		Kind: kind, Namespace: desired.Namespace, Name: desired.Name,
	})
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	if string(current.GetUID()) != expected.UID || current.GetGeneration() != expected.Generation {
		return fuzzcorpus.ResourceIdentity{}, errors.New("existing BurnchainPolicy identity differs from the journal")
	}
	var observed attacknetv1beta1.BurnchainPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &observed); err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	observedDigest, observedErr := canonical.ArtifactDigest(observed.Spec)
	desiredDigest, desiredErr := canonical.ArtifactDigest(desired.Spec)
	if observedErr != nil || desiredErr != nil || observedDigest != desiredDigest {
		return fuzzcorpus.ResourceIdentity{}, errors.New("existing BurnchainPolicy spec differs from the immutable descriptor")
	}
	return *expected, nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) waitForRestoredPolicy(
	ctx context.Context,
	desired *attacknetv1beta1.BurnchainPolicy,
	expected fuzzcorpus.ResourceIdentity,
) (fuzzcorpus.ResourceIdentity, error) {
	kind, _ := LookupKind("BurnchainPolicy")
	ref := ResourceRef{Kind: kind, Namespace: desired.Namespace, Name: desired.Name}
	for {
		current, err := runtimeBoundary.Backend.Get(ctx, ref)
		if err != nil {
			return fuzzcorpus.ResourceIdentity{}, err
		}
		if string(current.GetUID()) != expected.UID || current.GetGeneration() < expected.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("existing BurnchainPolicy identity differs from the journal")
		}
		var observed attacknetv1beta1.BurnchainPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &observed); err != nil {
			return fuzzcorpus.ResourceIdentity{}, err
		}
		observedStable := observed.Spec.DeepCopy()
		desiredStable := desired.Spec.DeepCopy()
		observedStable.Paused = false
		desiredStable.Paused = false
		observedDigest, observedErr := canonical.ArtifactDigest(observedStable)
		desiredDigest, desiredErr := canonical.ArtifactDigest(desiredStable)
		if observedErr != nil || desiredErr != nil || observedDigest != desiredDigest {
			return fuzzcorpus.ResourceIdentity{}, errors.New("existing BurnchainPolicy stable spec differs from the immutable descriptor")
		}
		if observed.Spec.Paused == desired.Spec.Paused &&
			observed.Status.ObservedGeneration == observed.Generation &&
			observed.Status.Phase == "Ready" {
			// Preserve the creation identity recorded in the journal. Generation and
			// resourceVersion advancement above are controller-owned observations,
			// not a new resource identity for teardown or retained evidence.
			return expected, nil
		}
		select {
		case <-ctx.Done():
			return fuzzcorpus.ResourceIdentity{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// EnsureTemplates materializes the descriptor-retained portable templates
// under attempt-local names. This keeps replay independent of the planning
// namespace while preserving exact UID-bound resume semantics.
func (runtimeBoundary *KubernetesFuzzRuntime) EnsureTemplates(
	ctx context.Context,
	faults []attacknetv1beta1.FaultCampaign,
	upgrades []attacknetv1beta1.UpgradeCampaign,
	expected []fuzzcorpus.ResourceIdentity,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if expected != nil && len(expected) != len(faults)+len(upgrades) {
		return nil, errors.New("journaled template inventory differs from the descriptor")
	}
	byKey := make(map[string]fuzzcorpus.ResourceIdentity, len(expected))
	for _, identity := range expected {
		key := identity.Kind + "/" + identity.Name
		if _, duplicate := byKey[key]; duplicate {
			return nil, errors.New("journaled template identity is duplicated")
		}
		byKey[key] = identity
	}
	result := make([]fuzzcorpus.ResourceIdentity, 0, len(faults)+len(upgrades))
	ensure := func(desired runtime.Object, kind, name string) error {
		var wanted *fuzzcorpus.ResourceIdentity
		if expected != nil {
			identity, found := byKey[kind+"/"+name]
			if !found {
				return fmt.Errorf("journaled %s %s is absent", kind, name)
			}
			wanted = &identity
		}
		identity, err := runtimeBoundary.ensureResource(ctx, desired, wanted, kind)
		if err != nil {
			return err
		}
		result = append(result, identity)
		return nil
	}
	for index := range faults {
		if err := ensure(&faults[index], "FaultCampaign", faults[index].Name); err != nil {
			return nil, err
		}
	}
	for index := range upgrades {
		if err := ensure(&upgrades[index], "UpgradeCampaign", upgrades[index].Name); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) EnsureRun(
	ctx context.Context,
	desired *attacknetv1beta1.AttacknetRun,
	expected *fuzzcorpus.ResourceIdentity,
) (fuzzcorpus.ResourceIdentity, error) {
	return runtimeBoundary.ensureResource(ctx, desired, expected, "AttacknetRun")
}

func (runtimeBoundary *KubernetesFuzzRuntime) ensureResource(
	ctx context.Context, desired runtime.Object,
	expected *fuzzcorpus.ResourceIdentity, kindName string,
) (fuzzcorpus.ResourceIdentity, error) {
	if runtimeBoundary.Backend == nil {
		return fuzzcorpus.ResourceIdentity{}, errors.New("Kubernetes backend is required")
	}
	kind, err := LookupKind(kindName)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(desired)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	removeNilObjectFields(value)
	object := &unstructured.Unstructured{Object: value}
	object.SetGroupVersionKind(kind.GVK)
	ref := ResourceRef{Kind: kind, Namespace: object.GetNamespace(), Name: object.GetName()}
	if expected != nil {
		current, err := runtimeBoundary.Backend.Get(ctx, ref)
		if err != nil {
			return fuzzcorpus.ResourceIdentity{}, err
		}
		if string(current.GetUID()) != expected.UID || current.GetGeneration() != expected.Generation {
			return fuzzcorpus.ResourceIdentity{}, errors.New("existing resource identity differs from the journal")
		}
		currentSpec, _, _ := unstructured.NestedFieldNoCopy(current.Object, "spec")
		desiredSpec, _, _ := unstructured.NestedFieldNoCopy(object.Object, "spec")
		currentDigest, currentErr := canonical.ArtifactDigest(currentSpec)
		desiredDigest, desiredErr := canonical.ArtifactDigest(desiredSpec)
		if currentErr != nil || desiredErr != nil || currentDigest != desiredDigest {
			return fuzzcorpus.ResourceIdentity{}, errors.New("existing resource spec differs from the immutable descriptor")
		}
		return *expected, nil
	}
	delete(object.Object, "status")
	current, err := runtimeBoundary.Backend.Get(ctx, ref)
	if err == nil {
		return resumableCreationIdentity(current, object)
	}
	if !apierrors.IsNotFound(err) {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	creator, ok := runtimeBoundary.Backend.(CreationBackend)
	if !ok {
		return fuzzcorpus.ResourceIdentity{}, errors.New("fuzz materialization requires create-only Kubernetes semantics")
	}
	created, err := creator.Create(ctx, object, kind)
	if apierrors.IsAlreadyExists(err) {
		current, getErr := runtimeBoundary.Backend.Get(ctx, ref)
		if getErr != nil {
			return fuzzcorpus.ResourceIdentity{}, getErr
		}
		return resumableCreationIdentity(current, object)
	}
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	return identityFor(created), nil
}

// removeNilObjectFields matches Kubernetes API storage semantics for typed
// optional object fields. Null array entries remain significant and are not
// removed or reordered.
func removeNilObjectFields(value map[string]any) {
	for key, item := range value {
		if item == nil {
			delete(value, key)
			continue
		}
		switch nested := item.(type) {
		case map[string]any:
			removeNilObjectFields(nested)
		case []any:
			for _, element := range nested {
				if object, ok := element.(map[string]any); ok {
					removeNilObjectFields(object)
				}
			}
		}
	}
}

var requiredFuzzProvenanceLabels = []string{
	"testing.stacks.org/fuzz-session",
	"testing.stacks.org/fuzz-trial",
	"testing.stacks.org/fuzz-attempt",
	"testing.stacks.org/fuzz-attempt-kind",
}

func resumableCreationIdentity(
	current, desired *unstructured.Unstructured,
) (fuzzcorpus.ResourceIdentity, error) {
	if current == nil || desired == nil || current.GetUID() == "" ||
		current.GetGeneration() < 1 || current.GetDeletionTimestamp() != nil {
		return fuzzcorpus.ResourceIdentity{}, errors.New("existing fuzz resource has no reusable immutable identity")
	}
	currentLabels, desiredLabels := current.GetLabels(), desired.GetLabels()
	for _, key := range requiredFuzzProvenanceLabels {
		if desiredLabels[key] == "" || currentLabels[key] != desiredLabels[key] {
			return fuzzcorpus.ResourceIdentity{}, errors.New("refusing to adopt existing resource without exact fuzz provenance")
		}
	}
	currentSpec, _, _ := unstructured.NestedFieldNoCopy(current.Object, "spec")
	desiredSpec, _, _ := unstructured.NestedFieldNoCopy(desired.Object, "spec")
	currentDigest, currentErr := canonical.ArtifactDigest(currentSpec)
	desiredDigest, desiredErr := canonical.ArtifactDigest(desiredSpec)
	if currentErr != nil || desiredErr != nil || currentDigest != desiredDigest {
		return fuzzcorpus.ResourceIdentity{}, errors.New("existing resource spec differs from the immutable descriptor")
	}
	return identityFor(current), nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) WaitNetworkReady(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity,
) error {
	barrier := readyInventoryBarrier{expectedGeneration: identity.Generation}
	return runtimeBoundary.waitFor(ctx, identity, barrier.observe)
}

type readyInventoryBarrier struct {
	digest             string
	expectedGeneration int64
}

func (barrier *readyInventoryBarrier) observe(object *unstructured.Unstructured) (bool, error) {
	if barrier.expectedGeneration < 1 || object.GetGeneration() != barrier.expectedGeneration {
		return false, errors.New("StacksNetwork generation changed before the Ready barrier")
	}
	observedGeneration, _, err := unstructured.NestedInt64(object.Object, "status", "observedGeneration")
	if err != nil {
		return false, err
	}
	if observedGeneration != barrier.expectedGeneration {
		barrier.digest = ""
		return false, nil
	}
	phase, _, err := unstructured.NestedString(object.Object, "status", "phase")
	if err != nil {
		return false, err
	}
	ready, _, err := unstructured.NestedBool(object.Object, "status", "inventoryReady")
	if err != nil {
		return false, err
	}
	digest, _, err := unstructured.NestedString(object.Object, "status", "inventoryDigest")
	if err != nil {
		return false, err
	}
	if phase != "Ready" || !ready || digest == "" {
		barrier.digest = ""
		return false, nil
	}
	if digest != barrier.digest {
		barrier.digest = digest
		return false, nil
	}
	return true, nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) WaitRunTerminal(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity,
) (fuzzsession.ObservedAttempt, error) {
	var result fuzzsession.ObservedAttempt
	err := runtimeBoundary.waitFor(ctx, identity, func(object *unstructured.Unstructured) (bool, error) {
		observed, terminal, err := runtimeBoundary.observeRunTerminal(ctx, identity, object)
		if terminal && err == nil {
			result = observed
		}
		return terminal, err
	})
	return result, err
}

func (runtimeBoundary *KubernetesFuzzRuntime) observeRunTerminal(
	ctx context.Context,
	identity fuzzcorpus.ResourceIdentity,
	object *unstructured.Unstructured,
) (fuzzsession.ObservedAttempt, bool, error) {
	if identity.Generation < 1 || object.GetGeneration() != identity.Generation {
		return fuzzsession.ObservedAttempt{}, false, errors.New("AttacknetRun generation changed before terminal observation")
	}
	var run attacknetv1beta1.AttacknetRun
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &run); err != nil {
		return fuzzsession.ObservedAttempt{}, false, err
	}
	if run.Status.ObservedGeneration != identity.Generation {
		return fuzzsession.ObservedAttempt{}, false, nil
	}
	if run.Status.Phase != "Passed" && run.Status.Phase != "Failed" && run.Status.Phase != "Inconclusive" {
		return fuzzsession.ObservedAttempt{}, false, nil
	}
	if run.Status.ScheduleRef == nil || run.Status.ScheduleRef.Digest == "" {
		return fuzzsession.ObservedAttempt{}, false, fmt.Errorf(
			"terminal run %s/%s has no sealed schedule: %s",
			run.Status.Phase, run.Status.Reason, run.Status.Message,
		)
	}
	violated := []string{}
	assertions := run.Status.ProtocolAssertions
	var baseline, during, recovery *attacknetv1beta1.ProtocolAssertionSetStatus
	if assertions != nil {
		baseline, during, recovery = assertions.Baseline, assertions.During, assertions.Recovery
	}
	for gate, status := range map[string]*attacknetv1beta1.ProtocolAssertionSetStatus{
		"baseline": baseline, "during": during, "recovery": recovery,
	} {
		if status == nil {
			continue
		}
		for _, assertion := range status.Results {
			if assertion.Outcome == "Violated" {
				violated = append(violated, gate+"/"+assertion.ID+":"+assertion.Outcome)
			}
		}
	}
	sort.Strings(violated)
	families, err := runtimeBoundary.mechanismFamilies(ctx, &run)
	if err != nil {
		return fuzzsession.ObservedAttempt{}, false, err
	}
	cohortDigest, err := versionCohortDigest(&run)
	if err != nil {
		return fuzzsession.ObservedAttempt{}, false, err
	}
	attribution := run.Status.Attribution
	if attribution == "" {
		attribution = "Attacknet"
	}
	result := fuzzsession.ObservedAttempt{
		Run: identity, ScheduleDigest: run.Status.ScheduleRef.Digest,
		Result: fuzzsession.TrialResult{
			Phase: run.Status.Phase, Reason: run.Status.Reason,
			Attribution: attribution, ViolatedAssertions: violated,
			MechanismFamilies:   families,
			IdentityDivergence:  identityDivergenceClass(run.Status.IdentityDivergence),
			VersionCohortDigest: cohortDigest,
		},
	}
	if run.Status.StartedAt != nil {
		result.StartedAt = run.Status.StartedAt.Time
	}
	if run.Status.FinishedAt != nil {
		result.FinishedAt = run.Status.FinishedAt.Time
	} else if run.Status.CompletedAt != nil {
		result.FinishedAt = run.Status.CompletedAt.Time
	}
	return result, true, nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) mechanismFamilies(
	ctx context.Context, run *attacknetv1beta1.AttacknetRun,
) ([]string, error) {
	set := map[string]bool{}
	for _, catalog := range run.Spec.CampaignCatalog {
		kind, _ := LookupKind("FaultCampaign")
		object, err := runtimeBoundary.Backend.Get(ctx, ResourceRef{Kind: kind, Namespace: run.Namespace, Name: catalog.CampaignRef})
		if err != nil {
			return nil, err
		}
		var campaign attacknetv1beta1.FaultCampaign
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &campaign); err != nil {
			return nil, err
		}
		digest, err := canonical.ArtifactDigest(campaign.Spec)
		if err != nil {
			return nil, err
		}
		if catalog.ExpectedGeneration == nil || string(campaign.UID) != catalog.ExpectedUID ||
			campaign.Generation != *catalog.ExpectedGeneration || digest != catalog.ExpectedSpecDigest {
			return nil, errors.New("fault template identity changed while classifying outcome")
		}
		for _, stage := range campaign.Spec.Stages {
			for _, action := range stage.Faults {
				set["fault:"+action.Fault.Type] = true
			}
		}
	}
	for _, catalog := range run.Spec.UpgradeCatalog {
		kind, _ := LookupKind("UpgradeCampaign")
		object, err := runtimeBoundary.Backend.Get(ctx, ResourceRef{Kind: kind, Namespace: run.Namespace, Name: catalog.UpgradeRef})
		if err != nil {
			return nil, err
		}
		var campaign attacknetv1beta1.UpgradeCampaign
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &campaign); err != nil {
			return nil, err
		}
		digest, err := canonical.ArtifactDigest(campaign.Spec)
		if err != nil {
			return nil, err
		}
		if catalog.ExpectedGeneration == nil || string(campaign.UID) != catalog.ExpectedUID ||
			campaign.Generation != *catalog.ExpectedGeneration || digest != catalog.ExpectedSpecDigest {
			return nil, errors.New("upgrade template identity changed while classifying outcome")
		}
		set["upgrade"] = true
	}
	result := make([]string, 0, len(set))
	for family := range set {
		result = append(result, family)
	}
	sort.Strings(result)
	return result, nil
}

func versionCohortDigest(run *attacknetv1beta1.AttacknetRun) (string, error) {
	if run.Status.ScheduleSummary == nil {
		return "", nil
	}
	type actorVersion struct {
		Name           string `json:"name"`
		RequestedImage string `json:"requestedImage"`
		RuntimeImageID string `json:"runtimeImageID"`
	}
	actors := make([]actorVersion, 0, len(run.Status.ScheduleSummary.NetworkInventory.Actors))
	for _, actor := range run.Status.ScheduleSummary.NetworkInventory.Actors {
		actors = append(actors, actorVersion{Name: actor.Name, RequestedImage: actor.RequestedImage, RuntimeImageID: actor.RuntimeImageID})
	}
	sort.Slice(actors, func(i, j int) bool { return actors[i].Name < actors[j].Name })
	if len(actors) == 0 {
		return "", nil
	}
	return canonical.Digest(actors)
}

func (runtimeBoundary *KubernetesFuzzRuntime) SuspendNetwork(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity,
) error {
	kind, _ := LookupKind("StacksNetwork")
	ref := ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name}
	current, err := runtimeBoundary.Backend.Get(ctx, ref)
	if err != nil {
		return err
	}
	if string(current.GetUID()) != identity.UID {
		return errors.New("network UID changed before suspension")
	}
	mutator, ok := runtimeBoundary.Backend.(ExactSuspensionBackend)
	if !ok {
		return errors.New("fuzz suspension requires an exact-identity Kubernetes mutation boundary")
	}
	suspended, err := mutator.SuspendExact(
		ctx, ref, current.GetUID(), current.GetGeneration(),
	)
	if err != nil {
		return err
	}
	if suspended.GetUID() != current.GetUID() || suspended.GetGeneration() < current.GetGeneration() {
		return errors.New("network identity changed during suspension")
	}
	suspendedIdentity := identityFor(suspended)
	return runtimeBoundary.waitFor(ctx, suspendedIdentity, func(object *unstructured.Unstructured) (bool, error) {
		if object.GetGeneration() != suspendedIdentity.Generation {
			return false, errors.New("network generation changed while waiting for suspension")
		}
		phase, _, err := unstructured.NestedString(object.Object, "status", "phase")
		if err != nil || phase != "Suspended" {
			return false, err
		}
		observed, _, err := unstructured.NestedInt64(object.Object, "status", "observedGeneration")
		return observed == suspendedIdentity.Generation, err
	})
}

func (runtimeBoundary *KubernetesFuzzRuntime) Capture(
	ctx context.Context, attempt fuzzsession.ObservedAttempt, maximumBytes int64,
) (fuzzsession.ObservedAttempt, error) {
	if runtimeBoundary.Incident == nil || runtimeBoundary.Logs == nil ||
		maximumBytes < 1024 ||
		attempt.StartedAt.IsZero() || attempt.FinishedAt.IsZero() ||
		!attempt.StartedAt.Before(attempt.FinishedAt) {
		return attempt, errors.New("complete evidence dependencies and run timestamps are required")
	}
	output, err := newCaptureWorkspace(runtimeBoundary.CorpusRoot)
	if err != nil {
		return attempt, err
	}
	defer os.RemoveAll(output)
	incidentMaximum := maximumBytes
	if incidentMaximum > 512<<20 {
		incidentMaximum = 512 << 20
	}
	artifactMaximum := int64(2 << 20)
	if artifactMaximum > incidentMaximum {
		artifactMaximum = incidentMaximum
	}
	incident, err := CaptureIncidentEvidence(ctx, runtimeBoundary.Incident, IncidentEvidenceOptions{
		Namespace: attempt.Network.Namespace, NetworkName: attempt.Network.Name,
		OutputDirectory: filepath.Join(output, "incident"), Timeout: 2 * time.Minute,
		MaxArtifactBytes: artifactMaximum, MaxTotalBytes: incidentMaximum,
		Now: runtimeBoundary.now,
	})
	if err != nil || len(incident.Errors) != 0 || len(incident.Omissions) != 0 {
		if err == nil {
			err = fmt.Errorf("incident evidence has %d errors and %d omissions", len(incident.Errors), len(incident.Omissions))
		}
		return attempt, err
	}
	if string(incident.Network.UID) != attempt.Network.UID ||
		incident.Network.Generation != attempt.Network.Generation ||
		incident.Network.ObservedGeneration != attempt.Network.Generation ||
		!incident.Network.InventoryReady || incident.Network.InventoryDigest == "" {
		return attempt, errors.New("network identity changed during incident capture")
	}
	logs, err := runtimeBoundary.Logs.Export(
		ctx, attempt.Network.Namespace, attempt.Network.Name,
		attempt.StartedAt.UTC(), attempt.FinishedAt.UTC(), filepath.Join(output, "loki"),
	)
	if err != nil || !logs.Complete {
		if err == nil {
			err = errors.New("Loki export is incomplete")
		}
		return attempt, err
	}
	live, err := runtimeBoundary.Incident.GetNetwork(
		ctx, attempt.Network.Namespace, attempt.Network.Name,
	)
	if err != nil || live.UID != incident.Network.UID ||
		live.Generation != attempt.Network.Generation ||
		live.Status.ObservedGeneration != attempt.Network.Generation ||
		live.Status.InventoryDigest != incident.Network.InventoryDigest {
		return attempt, errors.New("network identity changed after evidence capture")
	}
	terminalArtifacts, err := runtimeBoundary.captureTerminalRun(ctx, attempt)
	if err != nil {
		return attempt, err
	}
	attempt.InventoryDigest = incident.Network.InventoryDigest
	attempt.Result.EvidenceComplete = true
	attempt.Result.IncidentBundleSealed = true
	attempt.Result.LokiExportComplete = true
	artifacts, err := readEvidenceArtifacts(output, maximumBytes)
	if err != nil {
		return attempt, err
	}
	artifacts = append(artifacts, terminalArtifacts...)
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Name < artifacts[right].Name })
	manifest := struct {
		SchemaVersion   string   `json:"schemaVersion"`
		NetworkUID      string   `json:"networkUid"`
		InventoryDigest string   `json:"inventoryDigest"`
		ScheduleDigest  string   `json:"scheduleDigest"`
		Artifacts       []string `json:"artifacts"`
	}{
		SchemaVersion: "stacks-attacknet-fuzz-evidence/v1",
		NetworkUID:    attempt.Network.UID, InventoryDigest: attempt.InventoryDigest,
		ScheduleDigest: attempt.ScheduleDigest,
	}
	for _, artifact := range artifacts {
		manifest.Artifacts = append(manifest.Artifacts, artifact.Name)
	}
	encoded, err := canonical.Marshal(manifest)
	if err != nil {
		return attempt, err
	}
	attempt.Artifacts = append(artifacts, fuzzsession.Artifact{
		Name: "evidence-manifest", ContentType: "application/json", Data: encoded,
	})
	return attempt, nil
}

// newCaptureWorkspace isolates transient evidence files from semantic sessions.
func newCaptureWorkspace(corpusRoot string) (string, error) {
	return os.MkdirTemp(filepath.Join(corpusRoot, ".pending"), ".attacknet-capture-*")
}

func (runtimeBoundary *KubernetesFuzzRuntime) Teardown(
	ctx context.Context, attempt fuzzsession.ObservedAttempt,
) error {
	backend, ok := runtimeBoundary.Backend.(UIDDeleteBackend)
	if !ok {
		return errors.New("fuzz teardown requires UID-preconditioned deletion")
	}
	// AttacknetRun references StacksNetwork by name; it is not owned by the
	// network and therefore is not garbage-collected with it. Delete the exact
	// run first so its controller can prove child cleanup while the suspended
	// network identity is still available.
	if err := runtimeBoundary.deleteExactIdentity(ctx, backend, attempt.Run); err != nil {
		return err
	}
	for _, template := range attempt.Templates {
		if err := runtimeBoundary.deleteExactIdentity(ctx, backend, template); err != nil {
			return err
		}
	}
	live, err := runtimeBoundary.Incident.GetNetwork(
		ctx, attempt.Network.Namespace, attempt.Network.Name,
	)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil {
		if string(live.UID) != attempt.Network.UID || live.Status.Phase != "Suspended" {
			return errors.New("network identity changed or is not suspended before teardown")
		}
		kind, _ := LookupKind("StacksNetwork")
		ref := ResourceRef{Kind: kind, Namespace: live.Namespace, Name: live.Name}
		if err := backend.DeleteUID(ctx, ref, live.UID); err != nil {
			return err
		}
		if err := runtimeBoundary.waitDeleted(ctx, ref); err != nil {
			return err
		}
	}
	for _, policy := range attempt.Policies {
		if err := runtimeBoundary.deleteExactIdentity(ctx, backend, policy); err != nil {
			return err
		}
	}
	return nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) deleteExactIdentity(
	ctx context.Context, backend UIDDeleteBackend, identity fuzzcorpus.ResourceIdentity,
) error {
	kind, err := LookupKind(identity.Kind)
	if err != nil {
		return err
	}
	ref := ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name}
	current, err := runtimeBoundary.Backend.Get(ctx, ref)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(current.GetUID()) != identity.UID {
		return fmt.Errorf("%s %s/%s UID changed before teardown", identity.Kind, identity.Namespace, identity.Name)
	}
	if err := backend.DeleteUID(ctx, ref, current.GetUID()); err != nil {
		return err
	}
	return runtimeBoundary.waitDeleted(ctx, ref)
}

func (runtimeBoundary *KubernetesFuzzRuntime) waitDeleted(ctx context.Context, ref ResourceRef) error {
	timeout, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	for {
		_, err := runtimeBoundary.Backend.Get(timeout, ref)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-timeout.Done():
			return timeout.Err()
		case <-time.After(time.Second):
		}
	}
}

func (runtimeBoundary *KubernetesFuzzRuntime) waitFor(
	ctx context.Context,
	identity fuzzcorpus.ResourceIdentity,
	ready func(*unstructured.Unstructured) (bool, error),
) error {
	kind, err := LookupKind(identity.Kind)
	if err != nil {
		return err
	}
	ref := ResourceRef{Kind: kind, Namespace: identity.Namespace, Name: identity.Name}
	timeout, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	for {
		object, err := runtimeBoundary.Backend.Get(timeout, ref)
		if err != nil {
			return err
		}
		if string(object.GetUID()) != identity.UID {
			return errors.New("observed Kubernetes resource UID changed")
		}
		done, err := ready(object)
		if err != nil || done {
			return err
		}
		select {
		case <-timeout.Done():
			return timeout.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func identityFor(object *unstructured.Unstructured) fuzzcorpus.ResourceIdentity {
	return fuzzcorpus.ResourceIdentity{
		APIVersion: object.GetAPIVersion(), Kind: object.GetKind(),
		Namespace: object.GetNamespace(), Name: object.GetName(),
		UID: string(object.GetUID()), ResourceVersion: object.GetResourceVersion(),
		Generation: object.GetGeneration(),
	}
}

func identityDivergenceClass(value *attacknetv1beta1.IdentityDivergence) string {
	if value == nil {
		return ""
	}
	return "Detected"
}

func (runtimeBoundary *KubernetesFuzzRuntime) now() time.Time {
	if runtimeBoundary.Now == nil {
		return time.Now()
	}
	return runtimeBoundary.Now()
}

func readEvidenceArtifacts(root string, maximum int64) ([]fuzzsession.Artifact, error) {
	result := []fuzzsession.Artifact{}
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("evidence tree contains a non-regular file")
		}
		total += info.Size()
		if total > maximum || len(result) >= 4096 {
			return errors.New("evidence tree exceeds corpus bounds")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || strings.Contains(relative, "..") {
			return errors.New("evidence path escapes capture root")
		}
		contentType := "application/octet-stream"
		if filepath.Ext(path) == ".json" {
			if !json.Valid(data) {
				return errors.New("evidence JSON is invalid")
			}
			contentType = "application/json"
		}
		result = append(result, fuzzsession.Artifact{
			Name: filepath.ToSlash(relative), ContentType: contentType, Data: data,
		})
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, err
}
