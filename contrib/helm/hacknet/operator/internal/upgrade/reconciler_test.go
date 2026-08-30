package upgrade

import (
	"context"
	"errors"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
)

const (
	testBaselineDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testUpgradeDigest  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fixedObservations struct {
	snapshot protocolobservation.Snapshot
	err      error
}

func (reader fixedObservations) Read(context.Context, *attacknetv1beta1.StacksNetwork) (protocolobservation.Snapshot, error) {
	return reader.snapshot, reader.err
}

func TestReconcilerAdmitsStagesAndRecordsImmutableTransition(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)

	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil || !result.Requeue {
		t.Fatalf("persist finalizer: result=%#v err=%v", result, err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "Running" || campaign.Status.BaselineInventory == nil || campaign.Status.CurrentInventory == nil || len(campaign.Status.AppliedAssignments) != 1 {
		t.Fatalf("campaign was not durably admitted before rollout: %#v", campaign.Status)
	}

	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	setNetworkActorIdentity(t, network, "candidate:sealed", "containerd://"+testUpgradeDigest, "pod-upgraded")
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.StageReadySince == nil || len(campaign.Status.IdentityTransitions) != 1 || campaign.Status.IdentityTransitions[0].Actors[0] != "miner-1" {
		t.Fatalf("admitted identity transition was not recorded: %#v", campaign.Status)
	}

	now = now.Add(6 * time.Second)
	reconciler.Now = func() time.Time { return now }
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "Passed" || campaign.Status.CompletedAt == nil || campaign.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("stable upgrade did not pass: %#v", campaign.Status)
	}
}

func TestReconcilerRollsBackBeforeReportingFailure(t *testing.T) {
	now := time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Status.StageStartedAt = &metav1.Time{Time: now.Add(-2 * time.Minute)}
	if err := reconciler.Status().Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "RollingBack" || EffectiveAssignments(campaign) != nil {
		t.Fatalf("deadline did not start fail-closed rollback: %#v", campaign.Status)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "Failed" || !campaign.Status.RollbackComplete {
		t.Fatalf("baseline recovery was not proven before failure: %#v", campaign.Status)
	}
}

func TestReconcilerAcceptsStableWindowProvenBeforeDelayedReconcile(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)
	for range 2 {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	setNetworkActorIdentity(t, network, "candidate:sealed", "containerd://"+testUpgradeDigest, "pod-upgraded")
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Status.StageStartedAt = &metav1.Time{Time: now.Add(-2 * time.Minute)}
	campaign.Status.StageReadySince = &metav1.Time{Time: now.Add(-10 * time.Second)}
	if err := reconciler.Status().Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "Passed" {
		t.Fatalf("already-proven stable window was turned into a deadline failure: %#v", campaign.Status)
	}
}

func TestReconcilerClassifiesObservationLossAsInconclusive(t *testing.T) {
	now := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)
	reconciler.Observations = fixedObservations{err: errors.New("telemetry bridge unavailable")}
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Spec.Stages[0].Assertions = &attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout:    metav1.Duration{Duration: 5 * time.Minute},
		Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{ID: "telemetry", TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{Actors: []string{"miner-1"}}}},
	}
	if err := reconciler.Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	setNetworkActorIdentity(t, network, "candidate:sealed", "containerd://"+testUpgradeDigest, "pod-upgraded")
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Status.StageStartedAt = &metav1.Time{Time: now.Add(-2 * time.Minute)}
	if err := reconciler.Status().Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "RollingBack" || campaign.Status.RollbackTerminalPhase != "Inconclusive" || campaign.Status.Reason != "TelemetryUnavailable" {
		t.Fatalf("telemetry loss was not kept distinct from incompatibility: %#v", campaign.Status)
	}
}

func TestReconcilerTransitionsOnTerminalStageAssertionWithoutStatusChurn(t *testing.T) {
	now := time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Spec.Stages[0].Assertions = &attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout: metav1.Duration{Duration: 30 * time.Second},
		Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{
			ID: "progress",
			ChainProgress: &attacknetv1beta1.ChainProgressAssertion{
				Actors: []string{"miner-1"}, Chain: "stacks", MinimumDelta: 1,
				Window: metav1.Duration{Duration: 5 * time.Second},
			},
		}},
	}
	if err := reconciler.Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	setNetworkActorIdentity(t, network, "candidate:sealed", "containerd://"+testUpgradeDigest, "pod-upgraded")
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	reconciler.Observations = fixedObservations{snapshot: upgradeObservation(now, 12)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.StageAssertions == nil || campaign.Status.StageAssertions.Outcome != "Pending" {
		t.Fatalf("progress baseline was not retained: %#v", campaign.Status)
	}

	now = now.Add(6 * time.Second)
	reconciler.Now = func() time.Time { return now }
	reconciler.Observations = fixedObservations{snapshot: upgradeObservation(now, 12)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.Phase != "RollingBack" || campaign.Status.Reason != "ProtocolAssertionViolated" ||
		campaign.Status.StageAssertions == nil || campaign.Status.StageAssertions.Outcome != "Violated" {
		t.Fatalf("terminal assertion did not atomically start rollback: %#v", campaign.Status)
	}
}

func TestReconcilerPersistsProofWithStageReadyTransition(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	reconciler, request := upgradeTestReconciler(t, now)
	campaign := getUpgradeCampaign(t, reconciler, request.NamespacedName)
	campaign.Spec.Stages[0].Assertions = &attacknetv1beta1.ProtocolAssertionSetSpec{
		Timeout: metav1.Duration{Duration: 30 * time.Second},
		Assertions: []attacknetv1beta1.ProtocolAssertionSpec{{
			ID:                    "telemetry",
			TelemetryCompleteness: &attacknetv1beta1.TelemetryCompletenessAssertion{Actors: []string{"miner-1"}},
		}},
	}
	if err := reconciler.Update(context.Background(), campaign); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "network"}, network); err != nil {
		t.Fatal(err)
	}
	setNetworkActorIdentity(t, network, "candidate:sealed", "containerd://"+testUpgradeDigest, "pod-upgraded")
	if err := reconciler.Status().Update(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	reconciler.Observations = fixedObservations{snapshot: upgradeObservation(now, 12)}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	campaign = getUpgradeCampaign(t, reconciler, request.NamespacedName)
	if campaign.Status.StageReadySince == nil || campaign.Status.StageAssertions == nil || campaign.Status.StageAssertions.Outcome != "Proven" {
		t.Fatalf("proof and stage readiness were not persisted atomically: %#v", campaign.Status)
	}
}

func TestStageReadinessRequiresTheAdmittedConfigurationDigest(t *testing.T) {
	campaign := campaignFixture()
	campaign.Spec.Stages[0].Assignments[0].Config = &attacknetv1beta1.ConfigSource{
		ConfigMapRef:   &attacknetv1beta1.ConfigObjectRef{Name: "candidate-config", Key: "config.toml"},
		ExpectedDigest: digest,
	}
	network := &attacknetv1beta1.StacksNetwork{Status: attacknetv1beta1.StacksNetworkStatus{Actors: []attacknetv1beta1.ActorStatus{{
		Name: "signer-1", Image: "stacks:next", RuntimeImageID: "containerd://" + digest,
		Ready: true, IdentityReady: true, ConfigDigest: testUpgradeDigest,
	}}}}
	assignments := campaign.Spec.Stages[0].Assignments
	if stageActorsReady(campaign, network, assignments) {
		t.Fatal("stage accepted a runtime configuration other than the sealed actor/profile config")
	}
	network.Status.Actors[0].ConfigDigest = digest
	if !stageActorsReady(campaign, network, assignments) {
		t.Fatal("stage rejected the sealed actor/profile runtime configuration")
	}
}

type testDigestActor struct {
	ControllerRevision string `json:"controllerRevision"`
	Name               string `json:"name"`
	PodName            string `json:"podName"`
	PodUID             string `json:"podUID"`
	RequestedImage     string `json:"requestedImage"`
	Role               string `json:"role"`
	RuntimeImageID     string `json:"runtimeImageID"`
	ServiceName        string `json:"serviceName"`
	StatefulSetName    string `json:"statefulSetName"`
	StatefulSetUID     string `json:"statefulSetUID"`
}

func upgradeTestReconciler(t *testing.T, now time.Time) (*Reconciler, reconcile.Request) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid", Generation: 1},
		Spec:       attacknetv1beta1.StacksNetworkSpec{Nodes: []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner, Image: "stable:sealed"}}},
		Status:     attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: 1, Phase: "Ready", InventoryReady: true},
	}
	setNetworkActorIdentity(t, network, "stable:sealed", "containerd://"+testBaselineDigest, "pod-baseline")
	campaign := &attacknetv1beta1.UpgradeCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "roll", Namespace: "test", UID: "campaign-uid", Generation: 1},
		Spec: attacknetv1beta1.UpgradeCampaignSpec{
			NetworkRef: "network", RollbackOnFailure: true,
			Profiles: []attacknetv1beta1.UpgradeProfileSpec{{Name: "candidate", SourceKind: "prebuilt", Image: "candidate:sealed", ImageID: testUpgradeDigest, ProvenanceDigest: testUpgradeDigest, ConfigDigest: testUpgradeDigest}},
			Stages:   []attacknetv1beta1.UpgradeStageSpec{{Name: "miner", Assignments: []attacknetv1beta1.UpgradeAssignment{{Actor: "miner-1", Profile: "candidate"}}, StableFor: metav1.Duration{Duration: 5 * time.Second}, Deadline: metav1.Duration{Duration: time.Minute}}},
			Safety:   attacknetv1beta1.UpgradeSafetySpec{MaxParallelActors: 1, MaxMinerPercent: 100, MaxSignerWeightPercent: 100},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(network, campaign).WithObjects(network, campaign).Build()
	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme, Now: func() time.Time { return now }, Observations: fixedObservations{}}
	return reconciler, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test", Name: "roll"}}
}

func setNetworkActorIdentity(t *testing.T, network *attacknetv1beta1.StacksNetwork, image, runtimeID, podUID string) {
	t.Helper()
	network.Status.Actors = []attacknetv1beta1.ActorStatus{{
		Name: "miner-1", Role: "miner", ResourceName: "network-miner-1", Image: image,
		Ready: true, IdentityReady: true, ServiceName: "network-miner-1",
		StatefulSetUID: "statefulset-uid", CurrentRevision: "revision-1",
		PodName: "network-miner-1-0", PodUID: podUID, RuntimeImageID: runtimeID,
	}}
	payload := struct {
		Actors             []testDigestActor `json:"actors"`
		ObservedGeneration int64             `json:"observedGeneration"`
		SchemaVersion      string            `json:"schemaVersion"`
	}{ObservedGeneration: 1, SchemaVersion: "stacks-network-admitted-inventory/v1"}
	payload.Actors = append(payload.Actors, testDigestActor{
		ControllerRevision: "revision-1", Name: "miner-1", PodName: "network-miner-1-0",
		PodUID: podUID, RequestedImage: image, Role: "miner", RuntimeImageID: runtimeID,
		ServiceName: "network-miner-1", StatefulSetName: "network-miner-1", StatefulSetUID: "statefulset-uid",
	})
	digest, err := canonical.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest = digest
	network.Status.InventoryObservedAt = &metav1.Time{Time: time.Now().UTC()}
}

func upgradeObservation(observedAt time.Time, height float64) protocolobservation.Snapshot {
	name, help := "stacks_node_stacks_tip_height", "Stacks tip height"
	metricType := dto.MetricType_GAUGE
	return protocolobservation.Snapshot{
		NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", ObservedAt: observedAt,
		Actors: []protocolobservation.ActorSnapshot{{
			Source: protocolobservation.Source{
				Actor: "miner-1", Role: "miner", PodName: "network-miner-1-0", PodUID: "pod-upgraded",
				RuntimeImageID: "containerd://" + testUpgradeDigest, ServiceName: "network-miner-1",
				ObservedAt: observedAt, EvidenceClass: protocolobservation.EvidenceActorSelfReported,
			},
			Families: map[string]*dto.MetricFamily{name: {
				Name: &name, Help: &help, Type: &metricType,
				Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &height}}},
			}},
		}},
	}
}

func getUpgradeCampaign(t *testing.T, reconciler *Reconciler, key types.NamespacedName) *attacknetv1beta1.UpgradeCampaign {
	t.Helper()
	campaign := &attacknetv1beta1.UpgradeCampaign{}
	if err := reconciler.Get(context.Background(), key, campaign); err != nil {
		t.Fatal(err)
	}
	return campaign
}
