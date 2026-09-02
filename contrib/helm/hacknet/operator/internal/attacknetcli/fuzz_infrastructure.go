package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

const (
	localEscrowAPIVersion = "filesystem.attacknet.local/v1"
	localEscrowKind       = "LocalEscrow"
	sessionAnnotation     = "testing.stacks.org/fuzz-session"
	escrowContract        = "testing.stacks.org/capacity-escrow-contract"
)

// KubernetesFuzzInfrastructure owns the session Lease and the qualified local
// profile's physical capacity reservations. It cannot mutate actor workloads.
type KubernetesFuzzInfrastructure struct {
	client       kubernetes.Interface
	lease        *fuzzsession.LeaseManager
	namespace    string
	corpusRoot   string
	escrowImage  string
	pullPolicy   corev1.PullPolicy
	now          func() time.Time
	waitInterval time.Duration
}

// NewKubernetesFuzzInfrastructure constructs the local-kind infrastructure
// boundary used by the host-side typed CLI.
func NewKubernetesFuzzInfrastructure(
	client kubernetes.Interface,
	namespace, corpusRoot, escrowImage string,
	pullPolicy corev1.PullPolicy,
	now func() time.Time,
) (*KubernetesFuzzInfrastructure, error) {
	if client == nil || namespace == "" || corpusRoot == "" || escrowImage == "" {
		return nil, errors.New("Kubernetes client, namespace, corpus root, and escrow image are required")
	}
	if now == nil {
		now = time.Now
	}
	if pullPolicy == "" {
		pullPolicy = corev1.PullIfNotPresent
	}
	lease, err := fuzzsession.NewLeaseManager(
		client.CoordinationV1(), namespace, now, 90*time.Second,
	)
	if err != nil {
		return nil, err
	}
	return &KubernetesFuzzInfrastructure{
		client: client, lease: lease, namespace: namespace,
		corpusRoot: filepath.Clean(corpusRoot), escrowImage: escrowImage,
		pullPolicy: pullPolicy, now: now, waitInterval: time.Second,
	}, nil
}

func (infra *KubernetesFuzzInfrastructure) AcquireSession(
	ctx context.Context, holder string,
) (fuzzcorpus.ResourceIdentity, error) {
	lease, err := infra.lease.Acquire(ctx, holder)
	return leaseIdentity(lease), err
}

func (infra *KubernetesFuzzInfrastructure) RenewSession(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity, holder string,
) (fuzzcorpus.ResourceIdentity, error) {
	lease, err := infra.lease.Renew(ctx, leaseObject(identity, holder), holder)
	return leaseIdentity(lease), err
}

func (infra *KubernetesFuzzInfrastructure) ReleaseSession(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity, holder string,
) error {
	return infra.lease.Release(ctx, leaseObject(identity, holder), holder)
}

// SessionLease returns the exact current session Lease identity and holder.
func (infra *KubernetesFuzzInfrastructure) SessionLease(
	ctx context.Context,
) (fuzzcorpus.ResourceIdentity, string, error) {
	lease, err := infra.lease.Current(ctx)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, "", err
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	return leaseIdentity(lease), holder, nil
}

// BreakSession deletes only one exact stale session Lease.
func (infra *KubernetesFuzzInfrastructure) BreakSession(
	ctx context.Context, identity fuzzcorpus.ResourceIdentity, holder, reason string,
) error {
	if identity.Kind != "Lease" || identity.Namespace != infra.namespace || identity.UID == "" || identity.ResourceVersion == "" {
		return errors.New("exact session Lease identity is required")
	}
	return infra.lease.Break(ctx, types.UID(identity.UID), identity.ResourceVersion, holder, reason)
}

// Capacity obtains trusted kubelet filesystem summaries through the API
// server and local corpus filesystem headroom.
func (infra *KubernetesFuzzInfrastructure) Capacity(
	ctx context.Context, descriptor fuzzplan.Descriptor,
) (fuzzsession.CapacitySnapshot, error) {
	if filepath.Clean(descriptor.Corpus.Root) != infra.corpusRoot {
		return fuzzsession.CapacitySnapshot{}, errors.New("descriptor corpus root differs from runtime corpus root")
	}
	nodes, err := infra.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil || len(nodes.Items) == 0 {
		return fuzzsession.CapacitySnapshot{}, errors.New("no Kubernetes nodes are available for capacity admission")
	}
	snapshot := fuzzsession.CapacitySnapshot{ObservedAt: infra.now().UTC()}
	for _, node := range nodes.Items {
		capacity, err := infra.nodeCapacity(ctx, node.Name)
		if err != nil {
			return snapshot, err
		}
		snapshot.Nodes = append(snapshot.Nodes, capacity)
	}
	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].Name < snapshot.Nodes[j].Name })
	snapshot.CorpusAvailableBytes, err = fuzzsession.LocalAvailableBytes(infra.corpusRoot)
	return snapshot, err
}

// Reserve physically writes one local corpus escrow and one PVC-backed escrow
// on every Kubernetes node. Unsupported storage backends fail closed.
func (infra *KubernetesFuzzInfrastructure) Reserve(
	ctx context.Context, descriptor fuzzplan.Descriptor,
) ([]fuzzcorpus.ResourceIdentity, error) {
	if !descriptor.Capacity.RequirePhysicalEscrow {
		return nil, nil
	}
	storageClass, err := infra.qualifiedStorageClass(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	short := strings.TrimPrefix(descriptor.Digest, "sha256:")
	if len(short) < 12 {
		return nil, errors.New("session digest is invalid")
	}
	localName := ".capacity-escrow-" + short
	localPath, err := fuzzsession.CreatePhysicalEscrow(
		infra.corpusRoot, localName, descriptor.Capacity.EvidenceEscrowBytes, descriptor.Digest,
	)
	if err != nil {
		return nil, err
	}
	localUID, err := fuzzsession.PhysicalEscrowIdentity(localPath)
	if err != nil {
		_ = fuzzsession.ReleasePhysicalEscrow(localPath)
		return nil, err
	}
	resources := []fuzzcorpus.ResourceIdentity{{
		APIVersion: localEscrowAPIVersion, Kind: localEscrowKind,
		Namespace: infra.corpusRoot, Name: localName, UID: localUID,
	}}
	nodes, err := infra.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil || len(nodes.Items) == 0 {
		_ = infra.ReleaseReservation(ctx, resources)
		return nil, errors.New("cannot resolve nodes for physical storage escrow")
	}
	sort.Slice(nodes.Items, func(i, j int) bool { return nodes.Items[i].Name < nodes.Items[j].Name })
	for index, node := range nodes.Items {
		identities, err := infra.reserveNodeStorage(
			ctx, descriptor, short[:12], index, node.Name, storageClass,
		)
		if err != nil {
			_ = infra.ReleaseReservation(ctx, resources)
			return nil, err
		}
		resources = append(resources, identities...)
	}
	return resources, nil
}

// ReleaseReservation removes only the exact journaled file, Job, and PVC identities.
func (infra *KubernetesFuzzInfrastructure) ReleaseReservation(
	ctx context.Context, resources []fuzzcorpus.ResourceIdentity,
) error {
	var result error
	for index := len(resources) - 1; index >= 0; index-- {
		identity := resources[index]
		switch identity.Kind {
		case localEscrowKind:
			path := filepath.Join(identity.Namespace, identity.Name)
			current, err := fuzzsession.PhysicalEscrowIdentity(path)
			if os.IsNotExist(err) {
				// A crash can leave the exact ownership marker after the
				// payload was removed. Let the bounded release helper finish it.
				result = errors.Join(result, fuzzsession.ReleasePhysicalEscrow(path))
				continue
			}
			if err != nil || current != identity.UID {
				result = errors.Join(result, errors.New("local escrow identity changed before release"))
				continue
			}
			result = errors.Join(result, fuzzsession.ReleasePhysicalEscrow(path))
		case "PersistentVolumeClaim":
			current, getErr := infra.client.CoreV1().PersistentVolumeClaims(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(getErr) {
				continue
			}
			if getErr != nil || string(current.UID) != identity.UID {
				result = errors.Join(result, errors.New("capacity PVC identity changed before release"))
				continue
			}
			options := uidBoundDeleteOptions(types.UID(identity.UID), metav1.DeletePropagationBackground)
			err := infra.client.CoreV1().PersistentVolumeClaims(identity.Namespace).Delete(
				ctx, identity.Name, options,
			)
			if apierrors.IsNotFound(err) {
				err = nil
			}
			result = errors.Join(result, err)
		case "Job":
			current, getErr := infra.client.BatchV1().Jobs(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(getErr) {
				continue
			}
			if getErr != nil || string(current.UID) != identity.UID {
				result = errors.Join(result, errors.New("capacity Job identity changed before release"))
				continue
			}
			options := uidBoundDeleteOptions(types.UID(identity.UID), metav1.DeletePropagationBackground)
			err := infra.client.BatchV1().Jobs(identity.Namespace).Delete(ctx, identity.Name, options)
			if apierrors.IsNotFound(err) {
				err = nil
			}
			result = errors.Join(result, err)
		default:
			result = errors.Join(result, fmt.Errorf("refusing unknown reservation kind %q", identity.Kind))
		}
	}
	return result
}

type kubeletSummary struct {
	Node struct {
		FS      *filesystemStats `json:"fs"`
		Runtime *struct {
			ImageFS *filesystemStats `json:"imageFs"`
		} `json:"runtime"`
	} `json:"node"`
}

type filesystemStats struct {
	AvailableBytes *uint64 `json:"availableBytes"`
}

func (infra *KubernetesFuzzInfrastructure) nodeCapacity(
	ctx context.Context, node string,
) (fuzzsession.NodeCapacity, error) {
	data, err := infra.client.CoreV1().RESTClient().Get().AbsPath(
		"/api/v1/nodes", node, "proxy", "stats", "summary",
	).Do(ctx).Raw()
	if err != nil {
		return fuzzsession.NodeCapacity{}, fmt.Errorf("read kubelet capacity for %s: %w", node, err)
	}
	return parseKubeletCapacity(node, data)
}

func parseKubeletCapacity(node string, data []byte) (fuzzsession.NodeCapacity, error) {
	var summary kubeletSummary
	if err := json.Unmarshal(data, &summary); err != nil || summary.Node.FS == nil ||
		summary.Node.FS.AvailableBytes == nil || summary.Node.Runtime == nil ||
		summary.Node.Runtime.ImageFS == nil || summary.Node.Runtime.ImageFS.AvailableBytes == nil {
		return fuzzsession.NodeCapacity{}, fmt.Errorf("kubelet capacity for %s is incomplete", node)
	}
	root, image := *summary.Node.FS.AvailableBytes, *summary.Node.Runtime.ImageFS.AvailableBytes
	if root > uint64(^uint64(0)>>1) || image > uint64(^uint64(0)>>1) {
		return fuzzsession.NodeCapacity{}, fmt.Errorf("kubelet capacity for %s exceeds supported range", node)
	}
	return fuzzsession.NodeCapacity{
		Name: node, RootAvailableBytes: int64(root), ImageAvailableBytes: int64(image),
	}, nil
}

func (infra *KubernetesFuzzInfrastructure) qualifiedStorageClass(
	ctx context.Context, descriptor fuzzplan.Descriptor,
) (string, error) {
	classes, err := infra.client.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	explicit := explicitStorageClasses(descriptor)
	name := ""
	if len(explicit) > 1 {
		return "", errors.New("network uses multiple storage classes; one escrow cannot prove equivalent capacity")
	}
	for candidate := range explicit {
		name = candidate
	}
	if name == "" {
		for _, class := range classes.Items {
			if class.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" ||
				class.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
				if name != "" {
					return "", errors.New("multiple default storage classes are ambiguous")
				}
				name = class.Name
			}
		}
	}
	for _, class := range classes.Items {
		if class.Name == name {
			if class.Provisioner != "rancher.io/local-path" && class.Provisioner != "docker.io/hostpath" {
				return "", fmt.Errorf("storage class %s uses unqualified provisioner %s", name, class.Provisioner)
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("qualified actor storage class %q was not found", name)
}

func explicitStorageClasses(descriptor fuzzplan.Descriptor) map[string]struct{} {
	result := map[string]struct{}{}
	addWorkload := func(storageClass *string) {
		if storageClass != nil && *storageClass != "" {
			result[*storageClass] = struct{}{}
		}
	}
	defaults := descriptor.Network.Template.Spec.Defaults.Workload.Storage
	if defaults != nil {
		addWorkload(defaults.StorageClassName)
	}
	for _, actor := range descriptor.Network.Template.Spec.Burnchain.Nodes {
		if actor.Workload != nil && actor.Workload.Storage != nil {
			addWorkload(actor.Workload.Storage.StorageClassName)
		}
	}
	for _, actor := range descriptor.Network.Template.Spec.Nodes {
		if actor.Workload != nil && actor.Workload.Storage != nil {
			addWorkload(actor.Workload.Storage.StorageClassName)
		}
	}
	for _, set := range descriptor.Network.Template.Spec.SignerSets {
		for _, actor := range set.Members {
			if actor.SignerWorkload != nil && actor.SignerWorkload.Storage != nil {
				addWorkload(actor.SignerWorkload.Storage.StorageClassName)
			}
			if actor.NodeWorkload != nil && actor.NodeWorkload.Storage != nil {
				addWorkload(actor.NodeWorkload.Storage.StorageClassName)
			}
		}
	}
	for _, actor := range descriptor.Network.Template.Spec.RawActors {
		if actor.Workload != nil && actor.Workload.Storage != nil {
			addWorkload(actor.Workload.Storage.StorageClassName)
		}
	}
	if actor := descriptor.Network.Template.Spec.Enrollment; actor != nil &&
		actor.Workload != nil && actor.Workload.Storage != nil {
		addWorkload(actor.Workload.Storage.StorageClassName)
	}
	return result
}

func (infra *KubernetesFuzzInfrastructure) reserveNodeStorage(
	ctx context.Context,
	descriptor fuzzplan.Descriptor,
	short string,
	index int,
	node, storageClass string,
) ([]fuzzcorpus.ResourceIdentity, error) {
	name := fmt.Sprintf("fuzz-escrow-%s-%02d", short, index)
	quantity := *resource.NewQuantity(descriptor.Capacity.StorageEscrowBytes, resource.BinarySI)
	pvcContract, err := capacityPVCContract(descriptor, storageClass)
	if err != nil {
		return nil, err
	}
	desired := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: infra.namespace, Annotations: map[string]string{
			sessionAnnotation: descriptor.Digest,
			escrowContract:    pvcContract,
		}},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &storageClass,
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: quantity}},
		},
	}
	pvc, err := infra.client.CoreV1().PersistentVolumeClaims(infra.namespace).Create(ctx, desired, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		pvc, err = infra.client.CoreV1().PersistentVolumeClaims(infra.namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil && (pvc.Annotations[sessionAnnotation] != descriptor.Digest ||
			pvc.Annotations[escrowContract] != pvcContract ||
			pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != storageClass ||
			len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce ||
			pvc.Spec.Resources.Requests.Storage().Cmp(quantity) != 0) {
			return nil, errors.New("existing capacity PVC differs from the immutable session")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("create node capacity PVC: %w", err)
	}
	pvcIdentity := fuzzcorpus.ResourceIdentity{
		APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace,
		Name: pvc.Name, UID: string(pvc.UID), ResourceVersion: pvc.ResourceVersion,
	}
	jobIdentity, err := infra.writePVC(ctx, descriptor, short, index, node, pvc.Name)
	if err != nil {
		_ = infra.ReleaseReservation(ctx, []fuzzcorpus.ResourceIdentity{pvcIdentity})
		return nil, err
	}
	pvc, err = infra.client.CoreV1().PersistentVolumeClaims(infra.namespace).Get(ctx, pvc.Name, metav1.GetOptions{})
	if err != nil || string(pvc.UID) != pvcIdentity.UID {
		_ = infra.ReleaseReservation(ctx, []fuzzcorpus.ResourceIdentity{pvcIdentity, jobIdentity})
		return nil, errors.New("capacity PVC identity changed while proving allocation")
	}
	pvcIdentity.ResourceVersion = pvc.ResourceVersion
	return []fuzzcorpus.ResourceIdentity{pvcIdentity, jobIdentity}, nil
}

func capacityPVCContract(descriptor fuzzplan.Descriptor, storageClass string) (string, error) {
	return canonical.Digest(struct {
		SchemaVersion string `json:"schemaVersion"`
		Session       string `json:"session"`
		StorageClass  string `json:"storageClass"`
		Bytes         int64  `json:"bytes"`
		AccessMode    string `json:"accessMode"`
	}{"stacks-attacknet-capacity-pvc/v1", descriptor.Digest, storageClass, descriptor.Capacity.StorageEscrowBytes, string(corev1.ReadWriteOnce)})
}

func (infra *KubernetesFuzzInfrastructure) writePVC(
	ctx context.Context, descriptor fuzzplan.Descriptor, short string,
	index int, node, claim string,
) (fuzzcorpus.ResourceIdentity, error) {
	name := fmt.Sprintf("fuzz-escrow-writer-%s-%02d", short, index)
	desired, err := infra.escrowJob(descriptor, short, index, node, claim)
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, err
	}
	job, err := infra.client.BatchV1().Jobs(infra.namespace).Create(ctx, desired, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		job, err = infra.client.BatchV1().Jobs(infra.namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil && !sameEscrowJob(job, desired, descriptor.Digest) {
			return fuzzcorpus.ResourceIdentity{}, errors.New("existing capacity writer Job differs from the immutable session")
		}
	}
	if err != nil {
		return fuzzcorpus.ResourceIdentity{}, fmt.Errorf("create capacity writer Job: %w", err)
	}
	uid := job.UID
	identity := fuzzcorpus.ResourceIdentity{APIVersion: "batch/v1", Kind: "Job", Namespace: job.Namespace, Name: job.Name, UID: string(uid), ResourceVersion: job.ResourceVersion}
	timeout, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	for {
		current, err := infra.client.BatchV1().Jobs(infra.namespace).Get(timeout, name, metav1.GetOptions{})
		if err != nil {
			return fuzzcorpus.ResourceIdentity{}, err
		}
		if current.UID != uid {
			return fuzzcorpus.ResourceIdentity{}, errors.New("capacity writer Job identity changed")
		}
		if current.Status.Succeeded == 1 {
			identity.ResourceVersion = current.ResourceVersion
			return identity, nil
		}
		if current.Status.Failed > 0 {
			return fuzzcorpus.ResourceIdentity{}, errors.New("capacity writer Job failed")
		}
		select {
		case <-timeout.Done():
			return fuzzcorpus.ResourceIdentity{}, timeout.Err()
		case <-time.After(infra.waitInterval):
		}
	}
}

func (infra *KubernetesFuzzInfrastructure) escrowJob(
	descriptor fuzzplan.Descriptor, short string, index int, node, claim string,
) (*batchv1.Job, error) {
	name := fmt.Sprintf("fuzz-escrow-writer-%s-%02d", short, index)
	nonRoot, noPrivilege, readOnly := true, false, true
	user := int64(65532)
	grace := int64(10)
	args := []string{"--escrow-path", "/data/.attacknet-capacity-escrow-" + short, "--escrow-bytes", fmt.Sprint(descriptor.Capacity.StorageEscrowBytes)}
	desired := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: infra.namespace, Annotations: map[string]string{
			sessionAnnotation: descriptor.Digest,
		}},
		Spec: batchv1.JobSpec{BackoffLimit: int32ptr(0), Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"testing.stacks.org/component": "capacity-escrow"}},
			Spec: corev1.PodSpec{
				AutomountServiceAccountToken: &noPrivilege, RestartPolicy: corev1.RestartPolicyNever,
				// Let the scheduler select the exact requested node. Setting
				// nodeName directly bypasses scheduling and prevents
				// WaitForFirstConsumer storage classes from binding the PVC.
				NodeSelector: map[string]string{corev1.LabelHostname: node},
				Tolerations: []corev1.Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
					{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
				},
				TerminationGracePeriodSeconds: &grace,
				SecurityContext:               &corev1.PodSecurityContext{RunAsNonRoot: &nonRoot, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				Containers: []corev1.Container{{
					Name: "escrow-writer", Image: infra.escrowImage, ImagePullPolicy: infra.pullPolicy,
					Args:            args,
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noPrivilege, ReadOnlyRootFilesystem: &readOnly, RunAsNonRoot: &nonRoot, RunAsUser: &user, RunAsGroup: &user, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
					VolumeMounts:    []corev1.VolumeMount{{Name: "escrow", MountPath: "/data"}},
				}},
				Volumes: []corev1.Volume{{Name: "escrow", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}},
			},
		}},
	}
	contract, err := capacityWriterContract(desired, descriptor.Digest)
	if err != nil {
		return nil, err
	}
	desired.Annotations[escrowContract] = contract
	return desired, nil
}

func sameEscrowJob(current, desired *batchv1.Job, session string) bool {
	if current == nil || desired == nil || current.Annotations[sessionAnnotation] != session ||
		current.Annotations[escrowContract] == "" ||
		current.Annotations[escrowContract] != desired.Annotations[escrowContract] {
		return false
	}
	observed, err := capacityWriterContract(current, session)
	return err == nil && observed == current.Annotations[escrowContract]
}

type capacityWriterContractValue struct {
	SchemaVersion            string                    `json:"schemaVersion"`
	Session                  string                    `json:"session"`
	Component                string                    `json:"component"`
	Node                     string                    `json:"node"`
	Claim                    string                    `json:"claim"`
	Image                    string                    `json:"image"`
	PullPolicy               corev1.PullPolicy         `json:"pullPolicy"`
	Args                     []string                  `json:"args"`
	BackoffLimit             int32                     `json:"backoffLimit"`
	Automount                bool                      `json:"automountServiceAccountToken"`
	RestartPolicy            corev1.RestartPolicy      `json:"restartPolicy"`
	GraceSeconds             int64                     `json:"terminationGracePeriodSeconds"`
	PodRunAsNonRoot          bool                      `json:"podRunAsNonRoot"`
	Seccomp                  corev1.SeccompProfileType `json:"seccompProfile"`
	ContainerName            string                    `json:"containerName"`
	AllowPrivilegeEscalation bool                      `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool                      `json:"readOnlyRootFilesystem"`
	RunAsNonRoot             bool                      `json:"runAsNonRoot"`
	RunAsUser                int64                     `json:"runAsUser"`
	RunAsGroup               int64                     `json:"runAsGroup"`
	DroppedCapabilities      []corev1.Capability       `json:"droppedCapabilities"`
	CPURequest               string                    `json:"cpuRequest"`
	CPULimit                 string                    `json:"cpuLimit"`
	MemoryRequest            string                    `json:"memoryRequest"`
	MemoryLimit              string                    `json:"memoryLimit"`
	MountName                string                    `json:"mountName"`
	MountPath                string                    `json:"mountPath"`
	VolumeName               string                    `json:"volumeName"`
	Tolerations              []corev1.Toleration       `json:"tolerations"`
}

func capacityWriterContract(job *batchv1.Job, session string) (string, error) {
	if job == nil || job.Spec.BackoffLimit == nil || len(job.Spec.Template.Spec.Containers) != 1 ||
		len(job.Spec.Template.Spec.Volumes) != 1 ||
		len(job.Spec.Template.Spec.Containers[0].VolumeMounts) != 1 ||
		job.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim == nil ||
		job.Spec.Template.Spec.NodeSelector[corev1.LabelHostname] == "" {
		return "", errors.New("capacity writer Job shape is invalid")
	}
	pod := job.Spec.Template.Spec
	container := pod.Containers[0]
	security := container.SecurityContext
	if pod.AutomountServiceAccountToken == nil || pod.TerminationGracePeriodSeconds == nil ||
		pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || pod.SecurityContext.SeccompProfile == nil ||
		security == nil || security.AllowPrivilegeEscalation == nil || security.ReadOnlyRootFilesystem == nil ||
		security.RunAsNonRoot == nil || security.RunAsUser == nil || security.RunAsGroup == nil || security.Capabilities == nil {
		return "", errors.New("capacity writer Job security contract is incomplete")
	}
	value := capacityWriterContractValue{
		SchemaVersion: "stacks-attacknet-capacity-writer/v1", Session: session,
		Component: job.Spec.Template.Labels["testing.stacks.org/component"],
		Node:      pod.NodeSelector[corev1.LabelHostname], Claim: pod.Volumes[0].PersistentVolumeClaim.ClaimName,
		Image: container.Image, PullPolicy: container.ImagePullPolicy,
		Args: append([]string(nil), container.Args...), BackoffLimit: *job.Spec.BackoffLimit,
		Automount: *pod.AutomountServiceAccountToken, RestartPolicy: pod.RestartPolicy,
		GraceSeconds: *pod.TerminationGracePeriodSeconds, PodRunAsNonRoot: *pod.SecurityContext.RunAsNonRoot,
		Seccomp: pod.SecurityContext.SeccompProfile.Type, ContainerName: container.Name,
		AllowPrivilegeEscalation: *security.AllowPrivilegeEscalation,
		ReadOnlyRootFilesystem:   *security.ReadOnlyRootFilesystem, RunAsNonRoot: *security.RunAsNonRoot,
		RunAsUser: *security.RunAsUser, RunAsGroup: *security.RunAsGroup,
		DroppedCapabilities: append([]corev1.Capability(nil), security.Capabilities.Drop...),
		CPURequest:          container.Resources.Requests.Cpu().String(), CPULimit: container.Resources.Limits.Cpu().String(),
		MemoryRequest: container.Resources.Requests.Memory().String(), MemoryLimit: container.Resources.Limits.Memory().String(),
		MountName: container.VolumeMounts[0].Name, MountPath: container.VolumeMounts[0].MountPath,
		VolumeName:  pod.Volumes[0].Name,
		Tolerations: append([]corev1.Toleration(nil), pod.Tolerations...),
	}
	return canonical.Digest(value)
}

func leaseIdentity(value *coordinationv1.Lease) fuzzcorpus.ResourceIdentity {
	if value == nil {
		return fuzzcorpus.ResourceIdentity{}
	}
	return fuzzcorpus.ResourceIdentity{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: value.GetNamespace(), Name: value.GetName(), UID: string(value.GetUID()), ResourceVersion: value.GetResourceVersion()}
}

func leaseObject(identity fuzzcorpus.ResourceIdentity, holder string) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: identity.Name, Namespace: identity.Namespace,
			UID: types.UID(identity.UID), ResourceVersion: identity.ResourceVersion,
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
}

func int32ptr(value int32) *int32 { return &value }
