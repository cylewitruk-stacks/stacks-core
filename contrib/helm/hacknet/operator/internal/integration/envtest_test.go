//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	runcontroller "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/run"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
)

func TestMain(m *testing.M) {
	ctrl.SetLogger(logr.Discard())
	os.Exit(m.Run())
}

func TestTopologyManagerPublishesAndWithdrawsAdmittedInventory(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Fatal("KUBEBUILDER_ASSETS is required for integration tests")
	}
	crds, err := filepath.Abs("../../../crds")
	if err != nil {
		t.Fatal(err)
	}
	environment := &envtest.Environment{
		BinaryAssetsDirectory: assets,
		CRDDirectoryPaths:     []string{crds},
		ErrorIfCRDPathMissing: true,
	}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		appsv1.AddToScheme,
		corev1.AddToScheme,
		attacknetv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	const namespace = "attacknet-test"
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// controller-runtime retains registered names process-wide. Envtest may
		// repeat this isolated manager after the previous one has stopped.
		Controller: controllerconfig.Controller{SkipNameValidation: ptr(true)},
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{namespace: {}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciler := &topology.Reconciler{Client: mgr.GetClient(), Scheme: scheme}
	if err := reconciler.SetupWithManager(mgr, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = mgr.Start(ctx)
	}()
	if ok := mgr.GetCache().WaitForCacheSync(ctx); !ok {
		t.Fatal("cache did not synchronize")
	}
	direct, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}

	network := &attacknetv1alpha1.StacksNetwork{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1alpha1.GroupVersion.String(),
			Kind:       "StacksNetwork",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: namespace},
		Spec: attacknetv1alpha1.StacksNetworkSpec{
			Actors: []attacknetv1alpha1.ActorSpec{{
				Name:    "follower-1",
				Role:    "infrastructure",
				Image:   "example.invalid/actor@sha256:" + repeat("a", 64),
				Storage: &attacknetv1alpha1.StorageSpec{Enabled: ptr(false)},
			}},
		},
	}
	if err := direct.Create(ctx, network); err != nil {
		t.Fatal(err)
	}

	statefulSet := &appsv1.StatefulSet{}
	eventually(t, 10*time.Second, func() bool {
		return direct.Get(ctx, types.NamespacedName{
			Namespace: namespace,
			Name:      "network-follower-1",
		}, statefulSet) == nil
	})
	service := &corev1.Service{}
	if err := direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "network-follower-1"}, service); err != nil {
		t.Fatal(err)
	}
	statefulSetVersion, serviceVersion := statefulSet.ResourceVersion, service.ResourceVersion
	directReconciler := &topology.Reconciler{Client: direct, Scheme: scheme}
	if _, err := directReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: network.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(statefulSet), statefulSet); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(service), service); err != nil {
		t.Fatal(err)
	}
	if statefulSet.ResourceVersion != statefulSetVersion || service.ResourceVersion != serviceVersion {
		t.Fatalf("idempotent reconcile updated admitted workloads: StatefulSet %s -> %s, Service %s -> %s", statefulSetVersion, statefulSet.ResourceVersion, serviceVersion, service.ResourceVersion)
	}
	statefulSet.Status.ObservedGeneration = statefulSet.Generation
	statefulSet.Status.Replicas = 1
	statefulSet.Status.ReadyReplicas = 1
	statefulSet.Status.UpdatedReplicas = 1
	statefulSet.Status.CurrentRevision = "network-follower-1-r1"
	statefulSet.Status.UpdateRevision = statefulSet.Status.CurrentRevision
	if err := direct.Status().Update(ctx, statefulSet); err != nil {
		t.Fatal(err)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "network-follower-1-0",
			Namespace: namespace,
			Labels: map[string]string{
				"testing.stacks.org/managed-by": "stacks-hacknet-operator",
				"testing.stacks.org/network":    "network",
				"testing.stacks.org/actor":      "follower-1",
				"testing.stacks.org/role":       "infrastructure",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "actor",
				Image: "example.invalid/actor@sha256:" + repeat("a", 64),
			}},
		},
	}
	if err := direct.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{
		Type:   corev1.PodReady,
		Status: corev1.ConditionTrue,
	}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:    "actor",
		Ready:   true,
		ImageID: "docker-pullable://actor@sha256:" + repeat("b", 64),
	}}
	if err := direct.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}

	eventually(t, 10*time.Second, func() bool {
		current := &attacknetv1alpha1.StacksNetwork{}
		if direct.Get(ctx, client.ObjectKeyFromObject(network), current) != nil {
			return false
		}
		return current.Status.InventoryReady &&
			current.Status.InventoryDigest != "" &&
			len(current.Status.Actors) == 1 &&
			len(current.Status.Conditions) == 1 &&
			current.Status.Conditions[0].ObservedGeneration == current.Generation
	})
	if err := direct.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, func() bool {
		current := &attacknetv1alpha1.StacksNetwork{}
		if direct.Get(ctx, client.ObjectKeyFromObject(network), current) != nil {
			return false
		}
		return !current.Status.InventoryReady && current.Status.InventoryDigest == ""
	})
}

func TestRunAndFaultManagersExecuteOneShotCampaignEndToEnd(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Fatal("KUBEBUILDER_ASSETS is required for integration tests")
	}
	crds, err := filepath.Abs("../../../crds")
	if err != nil {
		t.Fatal(err)
	}
	environment := &envtest.Environment{BinaryAssetsDirectory: assets, CRDDirectoryPaths: []string{crds}, CRDs: chaosCRDs(), ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = environment.Stop() })
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, appsv1.AddToScheme, corev1.AddToScheme, attacknetv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	const namespace = "attacknet-run-test"
	mgr, err := ctrl.NewManager(config, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0", Controller: controllerconfig.Controller{SkipNameValidation: ptr(true)}, Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticSignerResolver{}
	faults := &fault.Reconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme, SignerSets: resolver}
	runs := &runcontroller.Reconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme, SignerSets: resolver}
	if err := faults.SetupWithManager(mgr, 1); err != nil {
		t.Fatal(err)
	}
	if err := runs.SetupWithManager(mgr, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache did not synchronize")
	}
	direct, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	if err := direct.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "attacknet-environment-lease", Namespace: namespace}, Data: map[string]string{"network": "network"}}); err != nil {
		t.Fatal(err)
	}
	index, weight := int32(1), 100.0
	key := "02" + strings.Repeat("1", 64)
	requested := "example.invalid/stacks@sha256:" + strings.Repeat("a", 64)
	runtimeImage := "docker-pullable://stacks@sha256:" + strings.Repeat("b", 64)
	network := &attacknetv1alpha1.StacksNetwork{TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "StacksNetwork"}, ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: namespace}, Spec: attacknetv1alpha1.StacksNetworkSpec{Actors: []attacknetv1alpha1.ActorSpec{{Name: "miner-1", Role: "miner", Image: requested}, {Name: "signer-1", Role: "signer", Image: requested, SignerIndex: &index, SignerWeight: &weight, SignerPublicKey: key}, {Name: "node-1", Role: "follower", Image: requested, SignerIndex: &index, SignerWeight: &weight, SignerPublicKey: key}}}}
	if err := direct.Create(ctx, network); err != nil {
		t.Fatal(err)
	}
	actors := make([]attacknetv1alpha1.ActorStatus, 0, len(network.Spec.Actors))
	for _, actor := range network.Spec.Actors {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "network-" + actor.Name + "-0", Namespace: namespace, Labels: map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/actor": actor.Name, "testing.stacks.org/role": actor.Role}}, Spec: corev1.PodSpec{NodeName: "worker", Containers: []corev1.Container{{Name: "actor", Image: requested}}}}
		if err := direct.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = "10.0.0." + fmt.Sprint(len(actors)+10)
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: runtimeImage}}
		if err := direct.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		actors = append(actors, attacknetv1alpha1.ActorStatus{Name: actor.Name, Role: actor.Role, ResourceName: "network-" + actor.Name, Image: requested, Ready: true, IdentityReady: true, ServiceName: "network-" + actor.Name, StatefulSetUID: "sts-" + actor.Name, CurrentRevision: "revision-1", PodName: pod.Name, PodUID: string(pod.UID), RuntimeImageID: runtimeImage})
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(network), network); err != nil {
		t.Fatal(err)
	}
	network.Status = attacknetv1alpha1.StacksNetworkStatus{ObservedGeneration: network.Generation, Phase: "Ready", DesiredActors: 3, ReadyActors: 3, InventoryReady: true, Actors: actors}
	payload, err := inventory.Build(network)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Status().Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	parameters := apixv1.JSON{Raw: []byte(`{}`)}
	template := &attacknetv1alpha1.FaultCampaign{TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "FaultCampaign"}, ObjectMeta: metav1.ObjectMeta{Name: "kill-miner", Namespace: namespace}, Spec: attacknetv1alpha1.FaultCampaignSpec{Template: true, NetworkRef: "network", Target: attacknetv1alpha1.FaultTarget{Actors: []string{"miner-1"}}, Fault: attacknetv1alpha1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: "5s", Parameters: parameters}, Safety: attacknetv1alpha1.FaultSafety{MaxUnavailableSignerPercent: 30, MaxUnavailableMinerPercent: 100, AllowMinerMajorityOutage: true}}}
	if err := direct.Create(ctx, template); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1alpha1.AttacknetRun{TypeMeta: metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "AttacknetRun"}, ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: namespace}, Spec: attacknetv1alpha1.AttacknetRunSpec{NetworkRef: "network", Seed: "integration-seed", DecisionAlgorithm: "hmac-sha256-decisions/v1", CampaignCatalog: []attacknetv1alpha1.CampaignCatalogEntry{{Name: "kill", CampaignRef: "kill-miner"}}, Sequence: []attacknetv1alpha1.RunInstruction{{ID: "kill-once", Campaign: "kill"}}, Budgets: attacknetv1alpha1.RunBudgets{MaxCampaigns: 1, MaxWallTimeSeconds: 60, MaxCumulativeFaultSeconds: 10, MaxActiveFaults: 1, MaxSignerImpactPercent: 30, MaxBurnchainFaults: 0, MaxInconclusiveCampaigns: 0}, StopPolicy: attacknetv1alpha1.StopPolicy{OnCampaignFailure: "Stop", OnInconclusive: "Stop", OnBudgetExhausted: "Stop", OnSuccess: "Continue"}, AttributionPolicy: attacknetv1alpha1.AttributionPolicy{RequiredOnFailure: true, RequireIncidentBundle: true, AllowedTerminalStates: []string{"Inconclusive"}}, Replay: attacknetv1alpha1.ReplaySpec{RequireSameResolvedImages: true}, Resume: attacknetv1alpha1.ResumeSpec{RequireSameSeed: true, RequireSameResolvedImages: true}, Minimization: attacknetv1alpha1.MinimizationSpec{Strategy: "DeltaDebug", RequireFreshNetwork: true}}}
	if err := direct.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	chaos := &unstructured.Unstructured{}
	chaos.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "PodChaos"})
	eventuallyWithDiagnostic(t, 15*time.Second, func() bool {
		return direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "run-1-kill-once"}, chaos) == nil
	}, func() string {
		current := &attacknetv1alpha1.AttacknetRun{}
		if err := direct.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
			return err.Error()
		}
		child := &attacknetv1alpha1.FaultCampaign{}
		if err := direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "run-1-kill-once"}, child); err != nil {
			return fmt.Sprintf("run phase=%s reason=%s message=%s; child=%v", current.Status.Phase, current.Status.Reason, current.Status.Message, err)
		}
		return fmt.Sprintf("run phase=%s reason=%s message=%s; child phase=%s reason=%s message=%s", current.Status.Phase, current.Status.Reason, current.Status.Message, child.Status.Phase, child.Status.Reason, child.Status.Message)
	})
	conditions := []any{map[string]any{"type": "AllInjected", "status": "True"}}
	_ = unstructured.SetNestedSlice(chaos.Object, conditions, "status", "conditions")
	if err := direct.Status().Update(ctx, chaos); err != nil {
		t.Fatal(err)
	}
	oldPod := &corev1.Pod{}
	if err := direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "network-miner-1-0"}, oldPod); err != nil {
		t.Fatal(err)
	}
	if err := direct.Delete(ctx, oldPod, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, func() bool { return direct.Get(ctx, client.ObjectKeyFromObject(oldPod), oldPod) != nil })
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "network-miner-1-1", Namespace: namespace, Labels: map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/actor": "miner-1", "testing.stacks.org/role": "miner"}}, Spec: corev1.PodSpec{NodeName: "worker", Containers: []corev1.Container{{Name: "actor", Image: requested}}}}
	if err := direct.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacement.Status.Phase = corev1.PodRunning
	replacement.Status.PodIP = "10.0.0.99"
	replacement.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	replacement.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: runtimeImage}}
	if err := direct.Status().Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(network), network); err != nil {
		t.Fatal(err)
	}
	for index := range network.Status.Actors {
		if network.Status.Actors[index].Name != "miner-1" {
			continue
		}
		network.Status.Actors[index].PodName = replacement.Name
		network.Status.Actors[index].PodUID = string(replacement.UID)
		network.Status.Actors[index].RuntimeImageID = runtimeImage
		network.Status.Actors[index].Ready = true
		network.Status.Actors[index].IdentityReady = true
	}
	payload, err = inventory.Build(network)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Status().Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	eventuallyWithDiagnostic(t, 20*time.Second, func() bool {
		current := &attacknetv1alpha1.AttacknetRun{}
		child := &attacknetv1alpha1.FaultCampaign{}
		return direct.Get(ctx, client.ObjectKeyFromObject(run), current) == nil &&
			direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "run-1-kill-once"}, child) == nil &&
			current.Status.Phase == "Passed" && current.Status.ScheduleRef != nil && len(current.Status.Decisions) == 1 &&
			current.Status.Cleanup != nil && current.Status.Cleanup.Completed && current.Status.FinishedAt != nil &&
			len(current.Status.IdentityTransitions) == 1 && len(current.Status.Conditions) == 1 && current.Status.Conditions[0].Status == metav1.ConditionTrue &&
			child.Status.Phase == "Passed" && len(child.Status.Conditions) == 1 && child.Status.Conditions[0].Status == metav1.ConditionTrue
	}, func() string {
		current := &attacknetv1alpha1.AttacknetRun{}
		child := &attacknetv1alpha1.FaultCampaign{}
		_ = direct.Get(ctx, client.ObjectKeyFromObject(run), current)
		_ = direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "run-1-kill-once"}, child)
		return fmt.Sprintf(
			"run phase=%s reason=%s decisions=%d transitions=%d conditions=%v; child phase=%s reason=%s conditions=%v message=%s",
			current.Status.Phase,
			current.Status.Reason,
			len(current.Status.Decisions),
			len(current.Status.IdentityTransitions),
			current.Status.Conditions,
			child.Status.Phase,
			child.Status.Reason,
			child.Status.Conditions,
			child.Status.Message,
		)
	})
}

type staticSignerResolver struct{}

func (staticSignerResolver) Resolve(_ context.Context, network *attacknetv1alpha1.StacksNetwork, _ []corev1.Pod) (signerset.Result, error) {
	weights := map[string]float64{}
	for _, actor := range network.Spec.Actors {
		if actor.SignerIndex != nil {
			weights[actor.Name] = 100
		}
	}
	return signerset.Result{WeightsByActor: weights, RewardCycle: 1, ObservedTotalWeight: 100, CanonicalThreshold: 70, SignerSetDigest: "sha256:" + strings.Repeat("c", 64), ObservedFrom: "node-1", WeightsMatch: true}, nil
}

func chaosCRDs() []*apixv1.CustomResourceDefinition {
	result := []*apixv1.CustomResourceDefinition{}
	for _, kind := range []string{"PodChaos", "NetworkChaos", "DNSChaos", "IOChaos", "TimeChaos"} {
		plural := strings.ToLower(kind)
		preserve := true
		result = append(result, &apixv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: plural + ".chaos-mesh.org"}, Spec: apixv1.CustomResourceDefinitionSpec{Group: "chaos-mesh.org", Names: apixv1.CustomResourceDefinitionNames{Plural: plural, Singular: plural, Kind: kind}, Scope: apixv1.NamespaceScoped, Versions: []apixv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true, Subresources: &apixv1.CustomResourceSubresources{Status: &apixv1.CustomResourceSubresourceStatus{}}, Schema: &apixv1.CustomResourceValidation{OpenAPIV3Schema: &apixv1.JSONSchemaProps{Type: "object", XPreserveUnknownFields: &preserve}}}}}})
	}
	return result
}

func eventually(t *testing.T, timeout time.Duration, predicate func() bool) {
	eventuallyWithDiagnostic(t, timeout, predicate, func() string { return "" })
}

func eventuallyWithDiagnostic(t *testing.T, timeout time.Duration, predicate func() bool, diagnostic func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition was not satisfied before timeout: %s", diagnostic())
}

func ptr[T any](value T) *T {
	return &value
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
