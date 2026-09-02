package attacknetcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

var (
	incidentNetworkGVR = schema.GroupVersionResource{Group: "testing.stacks.org", Version: "v1beta1", Resource: "stacksnetworks"}
	incidentOwnedGVRs  = []schema.GroupVersionResource{
		{Group: "", Version: "v1", Resource: "configmaps"},
		{Group: "", Version: "v1", Resource: "persistentvolumeclaims"},
		{Group: "", Version: "v1", Resource: "services"},
		{Group: "apps", Version: "v1", Resource: "deployments"},
		{Group: "apps", Version: "v1", Resource: "statefulsets"},
	}
)

// PodLogReader reads one bounded container log tail.
type PodLogReader interface {
	Read(context.Context, string, string, string, int64, int64) ([]byte, bool, error)
}

// ClientGoIncidentReader implements incident reads with client-go clients.
type ClientGoIncidentReader struct {
	dynamic dynamic.Interface
	core    kubernetes.Interface
	logs    PodLogReader
}

// NewClientGoIncidentReader constructs production uncached clients.
func NewClientGoIncidentReader(config *rest.Config) (*ClientGoIncidentReader, error) {
	if config == nil {
		return nil, fmt.Errorf("Kubernetes REST config is required")
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create incident dynamic client: %w", err)
	}
	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create incident typed client: %w", err)
	}
	return NewClientGoIncidentReaderWithClients(dynamicClient, coreClient, &clientGoPodLogReader{core: coreClient}), nil
}

// NewClientGoIncidentReaderWithClients supports fake-backed tests while
// retaining the same production read paths.
func NewClientGoIncidentReaderWithClients(dynamicClient dynamic.Interface, coreClient kubernetes.Interface, logs PodLogReader) *ClientGoIncidentReader {
	return &ClientGoIncidentReader{dynamic: dynamicClient, core: coreClient, logs: logs}
}

// GetNetwork reads and converts one current v1beta1 StacksNetwork.
func (reader *ClientGoIncidentReader) GetNetwork(ctx context.Context, namespace, name string) (*attacknetv1beta1.StacksNetwork, error) {
	if reader.dynamic == nil {
		return nil, fmt.Errorf("dynamic Kubernetes client is required")
	}
	object, err := reader.dynamic.Resource(incidentNetworkGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	network := &attacknetv1beta1.StacksNetwork{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, network); err != nil {
		return nil, fmt.Errorf("convert StacksNetwork: %w", err)
	}
	return network, nil
}

// ListOwnedResources lists network-labelled resources and retains only exact
// owner-UID matches.
func (reader *ClientGoIncidentReader) ListOwnedResources(ctx context.Context, namespace, network string, ownerUID types.UID, limit int) ([]*unstructured.Unstructured, error) {
	if reader.dynamic == nil {
		return nil, fmt.Errorf("dynamic Kubernetes client is required")
	}
	selector := labels.Set{incidentNetworkLabel: network}.AsSelector().String()
	result := make([]*unstructured.Unstructured, 0)
	for _, resource := range incidentOwnedGVRs {
		remaining := limit - len(result)
		if remaining <= 0 {
			break
		}
		list, err := reader.dynamic.Resource(resource).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: int64(remaining)})
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", resource.Resource, err)
		}
		for index := range list.Items {
			object := list.Items[index].DeepCopy()
			if controlledByUID(object.GetOwnerReferences(), ownerUID) {
				result = append(result, object)
			}
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return resourceArtifactPath(result[left]) < resourceArtifactPath(result[right])
	})
	return result, nil
}

// GetPod reads one Pod directly by admitted name.
func (reader *ClientGoIncidentReader) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	if reader.core == nil {
		return nil, fmt.Errorf("typed Kubernetes client is required")
	}
	return reader.core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

// ListEvents returns deduplicated Events involving the supplied immutable UIDs.
func (reader *ClientGoIncidentReader) ListEvents(ctx context.Context, namespace string, uids []types.UID, limit int) ([]corev1.Event, error) {
	if reader.core == nil {
		return nil, fmt.Errorf("typed Kubernetes client is required")
	}
	result := make([]corev1.Event, 0)
	seen := map[types.UID]struct{}{}
	for _, uid := range uids {
		if len(result) >= limit {
			break
		}
		selector := fields.OneTermEqualSelector("involvedObject.uid", string(uid)).String()
		events, err := reader.core.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{FieldSelector: selector, Limit: int64(limit - len(result))})
		if err != nil {
			return nil, fmt.Errorf("list events for UID %s: %w", uid, err)
		}
		for index := range events.Items {
			event := events.Items[index]
			if event.InvolvedObject.UID != uid {
				continue
			}
			if _, duplicate := seen[event.UID]; duplicate {
				continue
			}
			seen[event.UID] = struct{}{}
			result = append(result, *event.DeepCopy())
		}
	}
	sort.Slice(result, func(left, right int) bool {
		leftTime, rightTime := eventTimestamp(result[left]), eventTimestamp(result[right])
		if leftTime.Equal(&rightTime) {
			return result[left].Name < result[right].Name
		}
		return leftTime.Before(&rightTime)
	})
	return result, nil
}

// ReadPodLog reads a bounded tail and reports byte truncation explicitly.
func (reader *ClientGoIncidentReader) ReadPodLog(ctx context.Context, namespace, pod, container string, tailLines, maxBytes int64) ([]byte, bool, error) {
	if reader.logs == nil {
		return nil, false, fmt.Errorf("Pod log reader is required")
	}
	return reader.logs.Read(ctx, namespace, pod, container, tailLines, maxBytes)
}

type clientGoPodLogReader struct {
	core kubernetes.Interface
}

func (reader *clientGoPodLogReader) Read(ctx context.Context, namespace, pod, container string, tailLines, maxBytes int64) ([]byte, bool, error) {
	stream, err := reader.core.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, TailLines: &tailLines, Timestamps: true}).Stream(ctx)
	if err != nil {
		return nil, false, err
	}
	defer stream.Close()
	var buffer bytes.Buffer
	written, err := io.CopyN(&buffer, stream, maxBytes+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	truncated := written > maxBytes
	content := buffer.Bytes()
	if truncated {
		content = content[:maxBytes]
	}
	return append([]byte(nil), content...), truncated, nil
}

func controlledByUID(references []metav1.OwnerReference, uid types.UID) bool {
	for _, reference := range references {
		if reference.UID == uid && reference.Controller != nil && *reference.Controller {
			return true
		}
	}
	return false
}

func eventTimestamp(event corev1.Event) metav1.Time {
	if !event.EventTime.IsZero() {
		return metav1.NewTime(event.EventTime.Time)
	}
	if !event.LastTimestamp.IsZero() {
		return event.LastTimestamp
	}
	return event.CreationTimestamp
}

var _ IncidentEvidenceReader = (*ClientGoIncidentReader)(nil)
