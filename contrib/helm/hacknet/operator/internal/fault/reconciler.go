package fault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/signerset"
)

const (
	Finalizer        = "testing.stacks.org/fault-cleanup"
	environmentLease = "attacknet-environment-lease"
	mutationLease    = "attacknet-mutation-lease"
	clockPolicyZero  = "+0s\n"
)

var terminalPhases = map[string]bool{"Passed": true, "Failed": true, "Inconclusive": true}

var (
	errMutationIdentityChanged = errors.New("admitted mutation identity changed")
	errMutationContractChanged = errors.New("admitted mutation execution contract changed")
)

// mutationLeaseState distinguishes an unavailable environment lease from a
// mutation lease held by another writer.
type mutationLeaseState struct {
	Held               bool
	EnvironmentReady   bool
	EnvironmentMessage string
}

// Reconciler executes one bounded FaultCampaign and records durable evidence.
type Reconciler struct {
	client.Client
	APIReader              client.Reader
	Scheme                 *runtime.Scheme
	Probes                 ProbeClient
	Now                    func() time.Time
	IOPressureImage        string
	IOPressurePull         corev1.PullPolicy
	SignerSets             signerset.Resolver
	IOChaosArchitectures   map[string]bool
	TimeChaosArchitectures map[string]bool
}

type mutationIdentity struct {
	Kind, Name string
	GVK        schema.GroupVersionKind
}

// Reconcile advances one campaign by at most one durable state transition.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	campaign := &attacknetv1alpha1.FaultCampaign{}
	if err := r.Get(ctx, request.NamespacedName, campaign); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	current, err := r.campaignIsCurrent(ctx, campaign)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !current {
		return reconcile.Result{Requeue: true}, nil
	}
	if !campaign.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, r.reconcileDeletion(ctx, campaign)
	}
	if campaign.Spec.Template {
		return reconcile.Result{}, r.markTemplate(ctx, campaign)
	}
	if !controllerutil.ContainsFinalizer(campaign, Finalizer) {
		base := campaign.DeepCopy()
		controllerutil.AddFinalizer(campaign, Finalizer)
		return reconcile.Result{}, r.Patch(ctx, campaign, client.MergeFrom(base))
	}
	if terminalPhases[campaign.Status.Phase] {
		return reconcile.Result{}, r.reconcileTerminal(ctx, campaign)
	}
	serialized, err := r.isSerializedTurn(ctx, campaign)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !serialized && (campaign.Status.Phase == "" || campaign.Status.Phase == "Pending") {
		return reconcile.Result{RequeueAfter: 2 * time.Second}, r.transition(ctx, campaign, "Pending", "SerializedBehindActiveFault", "")
	}
	phase := campaign.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	key := types.NamespacedName{Namespace: campaign.Namespace, Name: campaign.Spec.NetworkRef}
	network := &attacknetv1alpha1.StacksNetwork{}
	var pods []corev1.Pod
	if phase == "Pending" {
		if err := r.Get(ctx, key, network); err != nil {
			return reconcile.Result{}, err
		}
		pods, err = r.networkPods(ctx, network.Name, network.Namespace)
	} else {
		var live inventory.LiveView
		live, err = inventory.ReadLiveView(ctx, r.APIReader, key)
		network, pods = live.Network, live.Pods
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	if phase == "Pending" && network.Status.Phase != "Ready" {
		return reconcile.Result{}, r.transition(ctx, campaign, "Pending", "NetworkNotReady", "")
	}
	if phase != "Pending" {
		lease, leaseErr := r.holdMutationLease(ctx, campaign, false)
		if leaseErr != nil {
			return reconcile.Result{}, leaseErr
		}
		if !lease.Held {
			cleanup, cleanupErr := r.removeMutation(ctx, campaign)
			if cleanupErr != nil {
				return reconcile.Result{}, cleanupErr
			}
			now := metav1.NewTime(r.now())
			next := *campaign.Status.DeepCopy()
			next.Cleanup = cleanup
			next.CompletedAt = &now
			message := "the mutation lease changed after admission; only the controller-owned mutation was removed"
			if !lease.EnvironmentReady {
				message = lease.EnvironmentMessage + "; only the controller-owned mutation was removed"
			}
			return reconcile.Result{}, r.patchStatus(ctx, campaign, statusTransition(next, campaign.Generation, "Failed", "MutationLeaseLost", message, r.now()))
		}
		identityChanged, err := r.enforceIdentity(ctx, campaign, network, pods)
		if err != nil {
			return reconcile.Result{}, err
		}
		if identityChanged {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
	}
	manifest := ManifestFromNetwork(network)
	var canonicalSignerSet *signerset.Result
	if phase == "Pending" {
		resolved, resolveErr := r.signerResolver().Resolve(ctx, network, pods)
		if resolveErr != nil {
			var transient *signerset.TransientError
			if errors.As(resolveErr, &transient) {
				return reconcile.Result{}, resolveErr
			}
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetAdmissionFailed", resolveErr)
		}
		canonicalSignerSet = &resolved
		manifest = applyCanonicalWeights(manifest, resolved.WeightsByActor)
	}
	compiled, err := Compile(campaign, manifest)
	if err != nil {
		return reconcile.Result{}, r.fail(ctx, campaign, "CampaignInvalid", err)
	}
	compiledDigest, err := canonical.ArtifactDigest(compiled.Resource.Object)
	if err != nil {
		return reconcile.Result{}, err
	}
	campaignSpecDigest, err := canonical.ArtifactDigest(campaign.Spec)
	if err != nil {
		return reconcile.Result{}, err
	}
	if phase == "Pending" {
		return r.admit(ctx, campaign, network, pods, compiled, compiledDigest, campaignSpecDigest, *canonicalSignerSet)
	}
	if !admissionMatches(campaign.Status.Admission, campaign, network, compiledDigest, campaignSpecDigest) {
		return reconcile.Result{}, r.fail(ctx, campaign, "AdmissionInputChanged", errors.New("admitted campaign or network changed"))
	}
	var result reconcile.Result
	var phaseErr error
	switch phase {
	case "Admitted":
		currentSignerSet, resolveErr := r.signerResolver().Resolve(ctx, network, pods)
		if resolveErr != nil {
			var transient *signerset.TransientError
			if errors.As(resolveErr, &transient) {
				return reconcile.Result{}, resolveErr
			}
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetChangedBeforeInjection", resolveErr)
		}
		if campaign.Status.Admission == nil || currentSignerSet.SignerSetDigest != campaign.Status.Admission.SignerSetDigest {
			return reconcile.Result{}, r.fail(ctx, campaign, "SignerSetChangedBeforeInjection", errors.New("canonical signer set changed after admission"))
		}
		phaseErr = r.inject(ctx, campaign, network, pods, compiled)
	case "Injecting":
		phaseErr = r.observeInjection(ctx, campaign, network, pods, compiled)
	case "Active":
		phaseErr = r.observeActive(ctx, campaign, network, compiled)
	case "Recovering":
		phaseErr = r.observeRecovery(ctx, campaign, network, pods, compiled)
	default:
		return reconcile.Result{}, r.fail(ctx, campaign, "UnknownPhase", fmt.Errorf("unsupported phase %s", phase))
	}
	if phaseErr != nil {
		switch {
		case errors.Is(phaseErr, errMutationIdentityChanged):
			return reconcile.Result{}, r.fail(ctx, campaign, "MutationIdentityChanged", phaseErr)
		case errors.Is(phaseErr, errMutationContractChanged):
			return reconcile.Result{}, r.fail(ctx, campaign, "MutationExecutionContractChanged", phaseErr)
		default:
			return reconcile.Result{}, phaseErr
		}
	}
	result.RequeueAfter = 2 * time.Second
	return result, nil
}

// networkPods returns the cached actor Pods used for ordinary reconciliation.
// Security-sensitive identity barriers use inventory.ReadLiveView instead.
func (r *Reconciler) networkPods(ctx context.Context, network, namespace string) ([]corev1.Pod, error) {
	list := &corev1.PodList{}
	if err := r.List(ctx, list, client.InNamespace(namespace), client.MatchingLabels{NetworkLabel: network}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Reconciler) signerResolver() signerset.Resolver {
	if r.SignerSets != nil {
		return r.SignerSets
	}
	return &signerset.HTTPResolver{}
}

func stableFaultName(parts ...string) string {
	candidate := strings.Join(parts, "-")
	if len(candidate) <= 63 {
		return candidate
	}
	digest, _ := canonical.ArtifactDigest(candidate)
	return strings.TrimRight(candidate[:52], "-") + "-" + strings.TrimPrefix(digest, "sha256:")[:10]
}
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
func ptr[T any](value T) *T { return &value }
func ternary[T any](condition bool, yes, no T) T {
	if condition {
		return yes
	}
	return no
}

// SetupWithManager registers campaign, topology, Pod, ConfigMap, and Chaos Mesh watches.
func (r *Reconciler) SetupWithManager(mgr manager.Manager, maxConcurrent int) error {
	if r.APIReader == nil {
		return errors.New("FaultCampaign reconciler requires an uncached Kubernetes API reader")
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &attacknetv1alpha1.FaultCampaign{}, "spec.networkRef", func(object client.Object) []string {
		return []string{object.(*attacknetv1alpha1.FaultCampaign).Spec.NetworkRef}
	}); err != nil {
		return fmt.Errorf("index FaultCampaign networkRef: %w", err)
	}
	mapNetwork := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		campaigns := &attacknetv1alpha1.FaultCampaignList{}
		if err := r.List(ctx, campaigns, client.InNamespace(object.GetNamespace()), client.MatchingFields{"spec.networkRef": object.GetName()}); err != nil {
			return nil
		}
		requests := make([]reconcile.Request, len(campaigns.Items))
		for index := range campaigns.Items {
			requests[index] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&campaigns.Items[index])}
		}
		return requests
	})
	mapLabels := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
		name := object.GetLabels()["testing.stacks.org/campaign"]
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
	})
	b := builder.ControllerManagedBy(mgr).For(&attacknetv1alpha1.FaultCampaign{}).Owns(&corev1.Pod{}).Watches(&attacknetv1alpha1.StacksNetwork{}, mapNetwork).Watches(&corev1.Pod{}, mapLabels).Watches(&corev1.ConfigMap{}, mapLabels).WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent})
	for _, definition := range registeredMechanisms() {
		if definition.Backend != chaosMeshBackend {
			continue
		}
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: definition.MutationKind})
		b = b.Watches(object, mapLabels)
	}
	return b.Complete(r)
}
