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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
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
		attacknetv1beta1.AddToScheme,
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
	reconciler := &topology.V1Beta1Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme,
	}
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
	invalidCampaign := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-admission", Namespace: namespace},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "invalid",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "mismatch", Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner-1"}},
					Fault: attacknetv1beta1.FaultSpec{Type: "dns", Action: "pod-kill", Mode: "all", Duration: metav1.Duration{Duration: time.Minute}},
				}},
			}},
			Safety: attacknetv1beta1.FaultSafety{MaxUnavailableSignerBasisPoints: 10_000, MaxUnavailableMinerBasisPoints: 10_000, MaxConcurrentFaults: 1},
		},
	}
	if err := direct.Create(ctx, invalidCampaign); !apierrors.IsInvalid(err) {
		t.Fatalf("API admission accepted an invalid type/action combination: %v", err)
	}
	invalidReorg := &attacknetv1beta1.FaultCampaign{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-reorg", Namespace: namespace},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{
				ID: "reorg",
				Faults: []attacknetv1beta1.FaultActionSpec{{
					ID: "replace", Target: attacknetv1beta1.FaultTarget{Actors: []string{"bitcoin-1"}, Mode: "one"},
					Fault: attacknetv1beta1.FaultSpec{
						Type: "burnchain-reorg", Mode: "one", Duration: metav1.Duration{Duration: time.Minute},
						BurnchainReorg: &attacknetv1beta1.BurnchainReorgFaultSpec{Depth: 2, ReplacementBlocks: 2},
					},
				}},
			}},
			Safety: attacknetv1beta1.FaultSafety{
				MaxUnavailableSignerBasisPoints: 10_000, MaxUnavailableMinerBasisPoints: 10_000,
				MaxConcurrentFaults: 1, AllowBurnchain: true, MaxBurnchainReorgDepth: 2,
				MaxBurnchainReplacementBlocks: 2,
			},
		},
	}
	if err := direct.Create(ctx, invalidReorg); !apierrors.IsInvalid(err) {
		t.Fatalf("API admission accepted a non-heavier replacement branch: %v", err)
	}
	invalidReorgTarget := invalidReorg.DeepCopy()
	invalidReorgTarget.Name = "invalid-reorg-target"
	invalidReorgTarget.Spec.Stages[0].Faults[0].Fault.BurnchainReorg.ReplacementBlocks = 3
	value := intstr.FromInt32(1)
	invalidReorgTarget.Spec.Stages[0].Faults[0].Target.Value = &value
	if err := direct.Create(ctx, invalidReorgTarget); !apierrors.IsInvalid(err) {
		t.Fatalf("API admission accepted a valued burnchain-reorg target: %v", err)
	}

	policy := &attacknetv1beta1.BurnchainPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: namespace},
		Spec: attacknetv1beta1.BurnchainPolicySpec{
			NetworkRef: "network", BitcoinNodeRef: "bitcoin-1", Cadence: metav1.Duration{Duration: time.Minute},
			Destinations: []attacknetv1beta1.BurnchainDestinationSpec{{WalletName: "wallet", Address: "bcrt1qtest"}},
		},
	}
	if err := direct.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.Phase = "Ready"
	if err := direct.Status().Update(ctx, policy); err != nil {
		t.Fatal(err)
	}

	network := &attacknetv1beta1.StacksNetwork{
		TypeMeta: metav1.TypeMeta{
			APIVersion: attacknetv1beta1.GroupVersion.String(),
			Kind:       "StacksNetwork",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: namespace},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults: attacknetv1beta1.NetworkDefaults{
				NodeImage: "example.invalid/node:test", SignerImage: "example.invalid/signer:test",
				BitcoinImage: "example.invalid/bitcoin@sha256:" + repeat("a", 64),
			},
			Burnchain: attacknetv1beta1.BurnchainTopologySpec{
				PolicyRef: corev1.LocalObjectReference{Name: policy.Name},
				Nodes: []attacknetv1beta1.BitcoinNodeSpec{{
					Name:     "bitcoin-1",
					Config:   attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "bitcoin-regtest/v1"}},
					Workload: &attacknetv1beta1.WorkloadPolicy{Storage: &attacknetv1beta1.StorageSpec{Enabled: ptr(false)}},
				}},
			},
		},
	}
	if err := direct.Create(ctx, network); err != nil {
		t.Fatal(err)
	}

	statefulSet := &appsv1.StatefulSet{}
	eventuallyWithDiagnostic(t, 10*time.Second, func() bool {
		return direct.Get(ctx, types.NamespacedName{
			Namespace: namespace,
			Name:      "network-bitcoin-1",
		}, statefulSet) == nil
	}, func() string {
		current := &attacknetv1beta1.StacksNetwork{}
		_ = direct.Get(ctx, client.ObjectKeyFromObject(network), current)
		return fmt.Sprintf("phase=%s reason=%v message=%s", current.Status.Phase, current.Status.Conditions, current.Status.ReadySummary)
	})
	service := &corev1.Service{}
	if err := direct.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "network-bitcoin-1"}, service); err != nil {
		t.Fatal(err)
	}
	statefulSetVersion, serviceVersion := statefulSet.ResourceVersion, service.ResourceVersion
	directReconciler := &topology.V1Beta1Reconciler{Client: direct, APIReader: direct, Scheme: scheme}
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
			Name:      "network-bitcoin-1-0",
			Namespace: namespace,
			Labels: map[string]string{
				"testing.stacks.org/managed-by": "stacks-hacknet-operator",
				"testing.stacks.org/network":    "network",
				"testing.stacks.org/actor":      "bitcoin-1",
				"testing.stacks.org/role":       "burnchain",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "actor",
				Image: "example.invalid/bitcoin@sha256:" + repeat("a", 64),
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

	eventuallyWithDiagnostic(t, 10*time.Second, func() bool {
		current := &attacknetv1beta1.StacksNetwork{}
		if direct.Get(ctx, client.ObjectKeyFromObject(network), current) != nil {
			return false
		}
		return current.Status.InventoryReady &&
			current.Status.InventoryDigest != "" &&
			len(current.Status.Actors) == 1 &&
			meta.IsStatusConditionTrue(current.Status.Conditions, "Ready") &&
			meta.FindStatusCondition(current.Status.Conditions, "Ready").ObservedGeneration == current.Generation
	}, func() string {
		current := &attacknetv1beta1.StacksNetwork{}
		_ = direct.Get(ctx, client.ObjectKeyFromObject(network), current)
		return fmt.Sprintf("phase=%s desired=%d ready=%d inventoryReady=%t actors=%#v conditions=%#v", current.Status.Phase, current.Status.DesiredActors, current.Status.ReadyActors, current.Status.InventoryReady, current.Status.Actors, current.Status.Conditions)
	})
	if err := direct.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	eventuallyWithDiagnostic(t, 10*time.Second, func() bool {
		current := &attacknetv1beta1.StacksNetwork{}
		if direct.Get(ctx, client.ObjectKeyFromObject(network), current) != nil {
			return false
		}
		return !current.Status.InventoryReady && current.Status.InventoryDigest == ""
	}, func() string {
		current := &attacknetv1beta1.StacksNetwork{}
		_ = direct.Get(ctx, client.ObjectKeyFromObject(network), current)
		return fmt.Sprintf("phase=%s inventoryReady=%t digest=%q actors=%#v", current.Status.Phase, current.Status.InventoryReady, current.Status.InventoryDigest, current.Status.Actors)
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
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, appsv1.AddToScheme, corev1.AddToScheme, attacknetv1alpha1.AddToScheme, attacknetv1beta1.AddToScheme} {
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
	protocolReader := &protocolobservation.Reader{APIReader: mgr.GetAPIReader()}
	faults := &fault.V1Beta1Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme,
		Observations: &fault.KubernetesTriggerObservationReader{Reader: mgr.GetAPIReader(), Protocol: protocolReader},
	}
	runs := &runcontroller.V1Beta1Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme, SignerSets: resolver,
		Observations: &runcontroller.KubernetesObservationReader{Reader: mgr.GetAPIReader(), Protocol: protocolReader},
	}
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
	requested := "example.invalid/stacks@sha256:" + strings.Repeat("a", 64)
	bitcoinRequested := "example.invalid/bitcoin@sha256:" + strings.Repeat("c", 64)
	runtimeImage := "docker-pullable://stacks@sha256:" + strings.Repeat("b", 64)
	bitcoinRuntime := "docker-pullable://bitcoin@sha256:" + strings.Repeat("d", 64)
	network := &attacknetv1beta1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: namespace},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults: attacknetv1beta1.NetworkDefaults{NodeImage: requested, SignerImage: requested, BitcoinImage: bitcoinRequested},
			Burnchain: attacknetv1beta1.BurnchainTopologySpec{
				PolicyRef: corev1.LocalObjectReference{Name: "clock"},
				Nodes: []attacknetv1beta1.BitcoinNodeSpec{{
					Name: "bitcoin-1", Config: attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "bitcoin-regtest/v1"}},
				}},
			},
			Nodes: []attacknetv1beta1.StacksNodeSpec{{
				Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner, BurnchainNodeRef: "bitcoin-1",
				Config: attacknetv1beta1.ConfigSource{SecretRef: &attacknetv1beta1.ConfigObjectRef{Name: "miner-config", Key: "config.toml"}},
			}},
		},
	}
	if err := direct.Create(ctx, network); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(network), network); err != nil {
		t.Fatal(err)
	}
	controller, blockDeletion := true, true
	if err := direct.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "attacknet-environment-lease", Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork", Name: network.Name,
				UID: network.UID, Controller: &controller, BlockOwnerDeletion: &blockDeletion,
			}},
		},
		Data: map[string]string{
			"network": network.Name, "owner": "stacksnetwork:" + string(network.UID),
			"purpose": "controller-owned-environment", "token": string(network.UID),
		},
	}); err != nil {
		t.Fatal(err)
	}
	type actorFixture struct {
		name, role, requested, runtime string
	}
	fixtures := []actorFixture{
		{name: "bitcoin-1", role: "burnchain", requested: bitcoinRequested, runtime: bitcoinRuntime},
		{name: "miner-1", role: "miner", requested: requested, runtime: runtimeImage},
	}
	actors := make([]attacknetv1beta1.ActorStatus, 0, len(fixtures))
	for index, actor := range fixtures {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "network-" + actor.name + "-0", Namespace: namespace, Labels: map[string]string{"testing.stacks.org/network": "network", "testing.stacks.org/actor": actor.name, "testing.stacks.org/role": actor.role}}, Spec: corev1.PodSpec{NodeName: "worker", Containers: []corev1.Container{{Name: "actor", Image: actor.requested}}}}
		if err := direct.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = "10.0.0." + fmt.Sprint(index+10)
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "actor", Ready: true, ImageID: actor.runtime}}
		if err := direct.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		actors = append(actors, attacknetv1beta1.ActorStatus{
			Name: actor.name, Role: actor.role, ResourceName: "network-" + actor.name, Image: actor.requested,
			Ready: true, ReadyReplicas: 1, UpdatedReplicas: 1, Generation: 1, ObservedGeneration: 1,
			IdentityReady: true, ServiceName: "network-" + actor.name, StatefulSetUID: "sts-" + actor.name,
			CurrentRevision: "revision-1", UpdateRevision: "revision-1", PodName: pod.Name,
			PodUID: string(pod.UID), RuntimeImageID: actor.runtime,
		})
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(network), network); err != nil {
		t.Fatal(err)
	}
	network.Status = attacknetv1beta1.StacksNetworkStatus{ObservedGeneration: network.Generation, Phase: "Ready", DesiredActors: 2, ReadyActors: 2, InventoryReady: true, Actors: actors}
	setBetaInventoryDigest(t, network)
	if err := direct.Status().Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	parameters := apixv1.JSON{Raw: []byte(`{}`)}
	template := &attacknetv1beta1.FaultCampaign{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "FaultCampaign"},
		ObjectMeta: metav1.ObjectMeta{Name: "kill-miner", Namespace: namespace},
		Spec: attacknetv1beta1.FaultCampaignSpec{
			Template: true, NetworkRef: "network",
			Stages: []attacknetv1beta1.FaultStageSpec{{ID: "restart", Faults: []attacknetv1beta1.FaultActionSpec{{
				ID: "kill", Target: attacknetv1beta1.FaultTarget{Actors: []string{"miner-1"}, Mode: "all"},
				Fault:              attacknetv1beta1.FaultSpec{Type: "pod", Action: "pod-kill", Mode: "one", Duration: metav1.Duration{Duration: time.Second}, Parameters: parameters},
				EffectAssertions:   []attacknetv1beta1.CampaignAssertion{{Type: "PodRestarted", Actor: "miner-1", TimeoutSeconds: 10}},
				RecoveryAssertions: []attacknetv1beta1.CampaignAssertion{{Type: "TargetReady", Actor: "miner-1", TimeoutSeconds: 10}},
			}}}},
			Safety: attacknetv1beta1.FaultSafety{MaxConcurrentFaults: 1, MaxUnavailableMinerBasisPoints: 10_000, AllowMinerMajorityOutage: true},
		},
	}
	if err := direct.Create(ctx, template); err != nil {
		t.Fatal(err)
	}
	run := &attacknetv1beta1.AttacknetRun{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "AttacknetRun"},
		ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: namespace},
		Spec: attacknetv1beta1.AttacknetRunSpec{
			NetworkRef: "network", Seed: "integration-seed", DecisionAlgorithm: "dependency-trigger-scheduler/v1",
			CampaignCatalog:   []attacknetv1beta1.CampaignCatalogEntry{{Name: "kill", CampaignRef: "kill-miner"}},
			Executions:        []attacknetv1beta1.RunExecutionSpec{{ID: "kill-once", Campaign: "kill"}},
			Budgets:           attacknetv1beta1.RunBudgets{MaxCampaigns: 1, MaxWallTimeSeconds: 60, MaxCumulativeFaultSeconds: 10, MaxActiveFaults: 1, MaxSignerImpactPercent: 30, MaxBurnchainFaults: 0, MaxInconclusiveCampaigns: 0},
			StopPolicy:        attacknetv1beta1.StopPolicy{OnCampaignFailure: "Stop", OnInconclusive: "Stop", OnBudgetExhausted: "Stop", OnSuccess: "Continue"},
			AttributionPolicy: attacknetv1beta1.AttributionPolicy{RequiredOnFailure: true, RequireIncidentBundle: true, AllowedTerminalStates: []string{"Inconclusive"}},
			Replay:            attacknetv1beta1.ReplaySpec{RequireSameResolvedImages: true},
			Resume:            attacknetv1beta1.ResumeSpec{RequireSameSeed: true, RequireSameResolvedImages: true},
			Minimization:      attacknetv1beta1.MinimizationSpec{Strategy: "DeltaDebug", RequireFreshNetwork: true},
		},
	}
	if err := direct.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	chaos := &unstructured.Unstructured{}
	eventuallyWithDiagnostic(t, 15*time.Second, func() bool {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "PodChaosList"})
		if err := direct.List(ctx, list, client.InNamespace(namespace)); err != nil || len(list.Items) != 1 {
			return false
		}
		chaos = list.Items[0].DeepCopy()
		return true
	}, func() string {
		current := &attacknetv1beta1.AttacknetRun{}
		if err := direct.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
			return err.Error()
		}
		child, err := betaRunChild(ctx, direct, namespace, run.Name)
		if err != nil {
			return fmt.Sprintf("run phase=%s reason=%s message=%s; child=%v", current.Status.Phase, current.Status.Reason, current.Status.Message, err)
		}
		return fmt.Sprintf("run phase=%s reason=%s message=%s; child phase=%s reason=%s message=%s", current.Status.Phase, current.Status.Reason, current.Status.Message, child.Status.Phase, child.Status.Reason, child.Status.Message)
	})
	// Pod identity may change only after the campaign has durably recorded the
	// admitted pod-kill mutation. Otherwise the run must fail closed rather than
	// infer that an unrelated replacement was caused by this campaign.
	eventuallyWithDiagnostic(t, 10*time.Second, func() bool {
		child, err := betaRunChild(ctx, direct, namespace, run.Name)
		active := err == nil && child.Status.Phase == "Running"
		return active && len(child.Status.Stages) == 1 && len(child.Status.Stages[0].Actions) == 1 &&
			child.Status.Stages[0].Actions[0].Mutation != nil
	}, func() string {
		child, err := betaRunChild(ctx, direct, namespace, run.Name)
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("child phase=%s reason=%s stages=%#v", child.Status.Phase, child.Status.Reason, child.Status.Stages)
	})
	mutationChild, err := betaRunChild(ctx, direct, namespace, run.Name)
	if err != nil {
		t.Fatal(err)
	}
	mutationChildUID := mutationChild.UID
	mutationChildResourceVersion := mutationChild.ResourceVersion
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
	setBetaInventoryDigest(t, network)
	if err := direct.Status().Update(ctx, network); err != nil {
		t.Fatal(err)
	}
	// Chaos Mesh reports AllInjected only after the pod-kill has taken effect.
	// Publishing this receipt before replacing the Pod would let the controller
	// correctly classify the asserted effect as absent.
	conditions := []any{map[string]any{"type": "AllInjected", "status": "True"}}
	_ = unstructured.SetNestedSlice(chaos.Object, conditions, "status", "conditions")
	if err := direct.Status().Update(ctx, chaos); err != nil {
		t.Fatal(err)
	}
	eventuallyWithDiagnostic(t, 20*time.Second, func() bool {
		current := &attacknetv1beta1.AttacknetRun{}
		child, err := betaRunChild(ctx, direct, namespace, run.Name)
		return direct.Get(ctx, client.ObjectKeyFromObject(run), current) == nil && err == nil &&
			current.Status.Phase == "Passed" && current.Status.ScheduleRef != nil && len(current.Status.Decisions) == 1 &&
			current.Status.Cleanup != nil && current.Status.Cleanup.Completed && current.Status.FinishedAt != nil &&
			len(current.Status.IdentityTransitions) == 1 && len(current.Status.Conditions) == 1 && current.Status.Conditions[0].Status == metav1.ConditionTrue &&
			child.Status.Phase == "Passed" && len(child.Status.Conditions) == 1 && child.Status.Conditions[0].Status == metav1.ConditionTrue
	}, func() string {
		current := &attacknetv1beta1.AttacknetRun{}
		_ = direct.Get(ctx, client.ObjectKeyFromObject(run), current)
		child, _ := betaRunChild(ctx, direct, namespace, run.Name)
		if child == nil {
			child = &attacknetv1beta1.FaultCampaign{}
		}
		return fmt.Sprintf(
			"run phase=%s reason=%s decisions=%d transitions=%d identity=%#v conditions=%v; mutationChildUID=%s mutationChildRV=%s child phase=%s reason=%s conditions=%v message=%s",
			current.Status.Phase,
			current.Status.Reason,
			len(current.Status.Decisions),
			len(current.Status.IdentityTransitions),
			current.Status.IdentityDivergence,
			current.Status.Conditions,
			mutationChildUID,
			mutationChildResourceVersion,
			child.Status.Phase,
			child.Status.Reason,
			child.Status.Conditions,
			child.Status.Message,
		)
	})
}

func setBetaInventoryDigest(t *testing.T, network *attacknetv1beta1.StacksNetwork) {
	t.Helper()
	legacy, err := topology.CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Generation = network.Generation
	legacy.Status = attacknetv1alpha1.StacksNetworkStatus{
		ObservedGeneration: network.Generation, InventoryReady: true,
	}
	for _, actor := range network.Status.Actors {
		legacy.Status.Actors = append(legacy.Status.Actors, attacknetv1alpha1.ActorStatus{
			Name: actor.Name, Role: actor.Role, ResourceName: actor.ResourceName, Image: actor.Image,
			Ready: actor.Ready, ServiceName: actor.ServiceName, StatefulSetUID: actor.StatefulSetUID,
			CurrentRevision: actor.CurrentRevision, PodName: actor.PodName, PodUID: actor.PodUID,
			RuntimeImageID: actor.RuntimeImageID, IdentityReady: actor.IdentityReady,
		})
	}
	payload, err := inventory.Build(legacy)
	if err != nil {
		t.Fatal(err)
	}
	network.Status.InventoryDigest, err = inventory.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
}

func betaRunChild(ctx context.Context, reader client.Reader, namespace, runName string) (*attacknetv1beta1.FaultCampaign, error) {
	children := &attacknetv1beta1.FaultCampaignList{}
	if err := reader.List(ctx, children, client.InNamespace(namespace), client.MatchingLabels{"testing.stacks.org/run": runName}); err != nil {
		return nil, err
	}
	if len(children.Items) != 1 {
		return nil, fmt.Errorf("run has %d child campaigns", len(children.Items))
	}
	return children.Items[0].DeepCopy(), nil
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
