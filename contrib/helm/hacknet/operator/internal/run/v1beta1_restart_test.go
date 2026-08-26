package run

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestBetaScheduleStoreSurvivesReconcilerRestart(t *testing.T) {
	run, network, admitted, templates, manifest := betaScheduleFixture()
	schedule, err := buildBetaSchedule(run, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run).Build()
	first := betaScheduleStore{writer: kube, reader: kube}
	reference, err := first.persist(context.Background(), run, schedule)
	if err != nil {
		t.Fatal(err)
	}
	// A new store has no in-memory state; successful read proves restart/resume
	// derives exclusively from the owner-bound immutable ConfigMap.
	second := betaScheduleStore{writer: kube, reader: kube}
	loaded, err := second.read(context.Background(), run, reference)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Integrity.Digest != schedule.Integrity.Digest || len(loaded.Executions) != 2 {
		t.Fatalf("restarted schedule reader lost state: %#v", loaded)
	}
}

func TestBetaResumeRequiresCompletedBoundaryAndPreservesSuffix(t *testing.T) {
	sourceRun, network, admitted, templates, manifest := betaScheduleFixture()
	sourceRun.Name = "source"
	source, err := buildBetaSchedule(sourceRun, network, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&attacknetv1beta1.AttacknetRun{}).WithObjects(sourceRun).Build()
	store := betaScheduleStore{writer: kube, reader: kube}
	reference, err := store.persist(context.Background(), sourceRun, source)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := betaJSON(betaDecision{ExecutionID: "first", Child: "source-execution-first", ChildUID: "child", Phase: "Passed", CompletedAt: time.Unix(10, 0).UTC()})
	stored := &attacknetv1beta1.AttacknetRun{}
	if err := kube.Get(context.Background(), clientKey(sourceRun), stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase = "Passed"
	stored.Status.ScheduleRef = &reference
	stored.Status.Decisions = []apixv1.JSON{decision}
	if err := kube.Status().Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}

	resumeRun, _, _, _, _ := betaScheduleFixture()
	resumeRun.Name = "resume"
	resumeRun.UID = "resume-uid"
	resumeRun.Spec.Executions = resumeRun.Spec.Executions[1:]
	resumeRun.Spec.Resume = attacknetv1beta1.ResumeSpec{Enabled: true, SourceRunRef: "source", AfterExecutionID: "first", RequireSameSeed: true, RequireSameResolvedImages: true}
	candidate := source
	candidate.Run.Name = resumeRun.Name
	candidate.Executions = append([]betaExecution(nil), source.Executions[1:]...)
	candidate.Network.UID = "fresh-network"
	candidate.Integrity = scheduleIntegrity{}
	candidate, err = sealBetaSchedule(candidate)
	if err != nil {
		t.Fatal(err)
	}
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube}
	resumed, err := reconciler.deriveBetaResume(context.Background(), resumeRun, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.Executions) != 1 || resumed.Executions[0].ID != "second" || len(resumed.Executions[0].Dependencies) != 0 || resumed.Replay.Strategy != "resume/v2" {
		t.Fatalf("resume did not preserve the verified suffix: %#v", resumed)
	}
}

func TestBetaReplayRebindsPortableCampaignsToFreshNetwork(t *testing.T) {
	sourceRun, sourceNetwork, admitted, templates, manifest := betaScheduleFixture()
	sourceRun.Name = "source"
	templates["partition"].Spec.NetworkRef = ""
	source, err := buildBetaSchedule(sourceRun, sourceNetwork, admitted, templates, manifest)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = attacknetv1beta1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&attacknetv1beta1.AttacknetRun{}).
		WithObjects(sourceRun).Build()
	store := betaScheduleStore{writer: kube, reader: kube}
	reference, err := store.persist(context.Background(), sourceRun, source)
	if err != nil {
		t.Fatal(err)
	}
	stored := &attacknetv1beta1.AttacknetRun{}
	if err := kube.Get(context.Background(), clientKey(sourceRun), stored); err != nil {
		t.Fatal(err)
	}
	stored.Status.Phase, stored.Status.ScheduleRef = "Passed", &reference
	if err := kube.Status().Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}

	replayRun, replayNetwork, replayInventory, _, replayManifest := betaScheduleFixture()
	replayRun.Name, replayRun.UID = "replay", "replay-uid"
	replayRun.Spec.NetworkRef = "fresh-network"
	replayRun.Spec.Replay = attacknetv1beta1.ReplaySpec{
		Enabled: true, SourceRunRef: sourceRun.Name,
		DescriptorURI:    "k8s://attacknetruns/source/resolved-schedule",
		DescriptorDigest: source.Integrity.Digest, AttemptID: "replay-attempt-1",
		RequireSameResolvedImages: true,
	}
	replayNetwork.Name, replayNetwork.UID = "fresh-network", "fresh-network-uid"
	replayInventory.ObservedGeneration = replayNetwork.Generation
	replayManifest.Network = replayNetwork.Name
	candidate, err := buildBetaSchedule(replayRun, replayNetwork, replayInventory, templates, replayManifest)
	if err != nil {
		t.Fatal(err)
	}
	reconciler := &V1Beta1Reconciler{Client: kube, APIReader: kube}
	replayed, err := reconciler.deriveBetaSchedule(context.Background(), replayRun, candidate, replayManifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, execution := range replayed.Executions {
		if execution.CampaignSpec.NetworkRef != replayNetwork.Name {
			t.Fatalf("replay retained source network binding: %#v", execution.CampaignSpec)
		}
		digest, digestErr := canonical.ArtifactDigest(execution.CampaignSpec)
		if digestErr != nil || digest != execution.CampaignSpecDigest {
			t.Fatalf("rebound execution digest is stale: got=%s want=%s err=%v", execution.CampaignSpecDigest, digest, digestErr)
		}
	}
}

func TestBetaStageAssertionResultsDoNotDoubleCountAggregates(t *testing.T) {
	result := apixv1.JSON{Raw: []byte(`{"assertion":"NetworkDegraded","outcome":"Proven"}`)}
	stage := attacknetv1beta1.FaultStageStatus{
		EffectResults: []apixv1.JSON{result},
		Actions:       []attacknetv1beta1.FaultActionStatus{{ID: "delay", EffectResults: []apixv1.JSON{result}}},
	}
	effect, recovery := betaStageAssertionResults(stage)
	if len(effect) != 1 || len(recovery) != 0 {
		t.Fatalf("action-owned assertion results = effect:%d recovery:%d", len(effect), len(recovery))
	}
	stage.Actions = nil
	effect, _ = betaStageAssertionResults(stage)
	if len(effect) != 1 {
		t.Fatalf("stage aggregate fallback results = %d", len(effect))
	}
}

func TestBetaDependencyObservationsExposeEvidenceMilestones(t *testing.T) {
	injected := metav1.NewTime(time.Unix(2, 0))
	recovered := metav1.NewTime(time.Unix(4, 0))
	completed := metav1.NewTime(time.Unix(5, 0))
	child := attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "child", UID: "child-uid", Annotations: map[string]string{betaExecutionAnnotation: "first"}},
		Status: attacknetv1beta1.FaultCampaignStatus{
			Phase: "Passed", CompletedAt: &completed,
			Stages:  []attacknetv1beta1.FaultStageStatus{{Actions: []attacknetv1beta1.FaultActionStatus{{Mutation: &attacknetv1beta1.ChaosReference{InjectedAt: &injected}}}}},
			Cleanup: &attacknetv1beta1.CleanupEvidence{AllRecovered: true, ObservedAt: recovered},
		},
	}
	observed := childDependencyObservations([]attacknetv1beta1.FaultCampaign{child})
	if len(observed) != 1 || len(observed[0].Transitions) != 3 || observed[0].Transitions[0].State != "Injected" || observed[0].Transitions[1].State != "Recovered" || observed[0].Transitions[2].State != "Terminal" {
		t.Fatalf("dependency evidence milestones are incomplete: %#v", observed)
	}
}
