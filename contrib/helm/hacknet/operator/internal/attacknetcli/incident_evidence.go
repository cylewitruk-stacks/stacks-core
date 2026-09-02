package attacknetcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const incidentNetworkLabel = "testing.stacks.org/network"

// IncidentEvidenceReader is the read-only Kubernetes boundary used by the
// incident collector. Implementations must read current API-server state.
type IncidentEvidenceReader interface {
	GetNetwork(context.Context, string, string) (*attacknetv1beta1.StacksNetwork, error)
	ListOwnedResources(context.Context, string, string, types.UID, int) ([]*unstructured.Unstructured, error)
	GetPod(context.Context, string, string) (*corev1.Pod, error)
	ListEvents(context.Context, string, []types.UID, int) ([]corev1.Event, error)
	ReadPodLog(context.Context, string, string, string, int64, int64) ([]byte, bool, error)
}

// IncidentEvidenceOptions bounds one forensic capture.
type IncidentEvidenceOptions struct {
	Namespace         string
	NetworkName       string
	OutputDirectory   string
	Timeout           time.Duration
	MaxConcurrency    int
	MaxArtifacts      int
	MaxArtifactBytes  int64
	MaxTotalBytes     int64
	MaxOwnedResources int
	MaxEvents         int
	LogTailLines      int64
	Now               func() time.Time
}

// IncidentEvidenceManifest binds every artifact and records incomplete reads
// without interpreting whether the network or experiment succeeded.
type IncidentEvidenceManifest struct {
	SchemaVersion string                     `json:"schemaVersion"`
	CapturedAt    time.Time                  `json:"capturedAt"`
	Network       IncidentNetworkIdentity    `json:"network"`
	Bounds        IncidentEvidenceBounds     `json:"bounds"`
	Artifacts     []IncidentEvidenceArtifact `json:"artifacts"`
	Omissions     []IncidentEvidenceProblem  `json:"omissions,omitempty"`
	Errors        []IncidentEvidenceProblem  `json:"errors,omitempty"`
}

// IncidentNetworkIdentity binds capture scope to controller-admitted identity.
type IncidentNetworkIdentity struct {
	Namespace          string    `json:"namespace"`
	Name               string    `json:"name"`
	UID                types.UID `json:"uid"`
	Generation         int64     `json:"generation"`
	ObservedGeneration int64     `json:"observedGeneration"`
	InventoryReady     bool      `json:"inventoryReady"`
	InventoryDigest    string    `json:"inventoryDigest,omitempty"`
}

// IncidentEvidenceBounds records the enforced resource and byte limits.
type IncidentEvidenceBounds struct {
	TimeoutSeconds    int64 `json:"timeoutSeconds"`
	MaxConcurrency    int   `json:"maxConcurrency"`
	MaxArtifacts      int   `json:"maxArtifacts"`
	MaxArtifactBytes  int64 `json:"maxArtifactBytes"`
	MaxTotalBytes     int64 `json:"maxTotalBytes"`
	MaxOwnedResources int   `json:"maxOwnedResources"`
	MaxEvents         int   `json:"maxEvents"`
	LogTailLines      int64 `json:"logTailLines"`
}

// IncidentEvidenceArtifact describes one content-addressed bundle member.
type IncidentEvidenceArtifact struct {
	Path      string `json:"path"`
	MediaType string `json:"mediaType"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Source    string `json:"source"`
}

// IncidentEvidenceProblem records a bounded omission or read error.
type IncidentEvidenceProblem struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type incidentArtifact struct {
	metadata IncidentEvidenceArtifact
	content  []byte
}

type incidentBundle struct {
	options   IncidentEvidenceOptions
	artifacts []incidentArtifact
	omissions []IncidentEvidenceProblem
	errors    []IncidentEvidenceProblem
	total     int64
	paths     map[string]struct{}
}

// CaptureIncidentEvidence captures identity-bound Kubernetes evidence and
// atomically publishes a directory containing artifacts plus manifest.json.
func CaptureIncidentEvidence(ctx context.Context, reader IncidentEvidenceReader, options IncidentEvidenceOptions) (IncidentEvidenceManifest, error) {
	options, err := normalizeIncidentEvidenceOptions(options)
	if err != nil {
		return IncidentEvidenceManifest{}, err
	}
	if reader == nil {
		return IncidentEvidenceManifest{}, errors.New("incident evidence reader is required")
	}
	captureContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	network, err := reader.GetNetwork(captureContext, options.Namespace, options.NetworkName)
	if err != nil {
		return IncidentEvidenceManifest{}, fmt.Errorf("read StacksNetwork %s/%s: %w", options.Namespace, options.NetworkName, err)
	}
	if network.UID == "" || network.Namespace != options.Namespace || network.Name != options.NetworkName {
		return IncidentEvidenceManifest{}, errors.New("observed StacksNetwork identity does not match requested scope")
	}
	bundle := &incidentBundle{options: options, paths: map[string]struct{}{}}
	if !network.Status.InventoryReady || network.Status.InventoryDigest == "" {
		bundle.omit("inventory", "admitted-inventory-not-ready", "controller status does not contain a complete admitted inventory")
	}
	if err := bundle.addJSON("resources/stacksnetwork.json", "kubernetes-api", network); err != nil {
		return IncidentEvidenceManifest{}, err
	}
	if err := bundle.addJSON("identity/admitted-actors.json", "stacksnetwork-status", map[string]any{
		"observedGeneration": network.Status.ObservedGeneration,
		"inventoryReady":     network.Status.InventoryReady,
		"inventoryDigest":    network.Status.InventoryDigest,
		"actors":             network.Status.Actors,
	}); err != nil {
		return IncidentEvidenceManifest{}, err
	}

	relevantUIDs := map[types.UID]struct{}{network.UID: {}}
	resources, resourceErr := reader.ListOwnedResources(captureContext, network.Namespace, network.Name, network.UID, options.MaxOwnedResources+1)
	if resourceErr != nil {
		bundle.fail("owned-resources", "api-read-failed", resourceErr.Error())
	} else {
		if len(resources) > options.MaxOwnedResources {
			bundle.omit("owned-resources", "resource-limit", fmt.Sprintf("captured first %d resources", options.MaxOwnedResources))
			resources = resources[:options.MaxOwnedResources]
		}
		sort.Slice(resources, func(left, right int) bool {
			return resourceArtifactPath(resources[left]) < resourceArtifactPath(resources[right])
		})
		for _, resource := range resources {
			if resource.GetUID() != "" {
				relevantUIDs[resource.GetUID()] = struct{}{}
			}
			if err := bundle.addJSON(resourceArtifactPath(resource), "kubernetes-api", resource.Object); err != nil {
				bundle.fail(resourceArtifactPath(resource), "artifact-rejected", err.Error())
			}
		}
	}

	logTasks := make([]incidentLogTask, 0)
	seenPods := map[string]struct{}{}
	for _, actor := range network.Status.Actors {
		scope := "actor/" + actor.Name
		if actor.PodName == "" || actor.PodUID == "" {
			bundle.omit(scope, "admitted-pod-identity-missing", "status has no exact Pod name and UID")
			continue
		}
		if _, duplicate := seenPods[actor.PodName]; duplicate {
			continue
		}
		seenPods[actor.PodName] = struct{}{}
		pod, podErr := reader.GetPod(captureContext, network.Namespace, actor.PodName)
		if podErr != nil {
			bundle.fail(scope, "pod-read-failed", podErr.Error())
			continue
		}
		if pod.UID != types.UID(actor.PodUID) {
			bundle.omit(scope, "admitted-pod-replaced", fmt.Sprintf("expected UID %s, observed %s; replacement logs were not captured", actor.PodUID, pod.UID))
			continue
		}
		relevantUIDs[pod.UID] = struct{}{}
		if err := bundle.addJSON("pods/"+safeSegment(pod.Name)+".json", "kubernetes-api", pod); err != nil {
			bundle.fail(scope, "pod-artifact-rejected", err.Error())
		}
		for _, container := range append(append([]corev1.Container(nil), pod.Spec.InitContainers...), pod.Spec.Containers...) {
			logTasks = append(logTasks, incidentLogTask{pod: pod.Name, container: container.Name})
		}
	}

	uids := make([]types.UID, 0, len(relevantUIDs))
	for uid := range relevantUIDs {
		uids = append(uids, uid)
	}
	sort.Slice(uids, func(left, right int) bool { return uids[left] < uids[right] })
	events, eventErr := reader.ListEvents(captureContext, network.Namespace, uids, options.MaxEvents+1)
	if eventErr != nil {
		bundle.fail("events", "api-read-failed", eventErr.Error())
	} else {
		if len(events) > options.MaxEvents {
			bundle.omit("events", "event-limit", fmt.Sprintf("captured first %d events", options.MaxEvents))
			events = events[:options.MaxEvents]
		}
		if err := bundle.addJSON("events/events.json", "kubernetes-api", events); err != nil {
			bundle.fail("events", "artifact-rejected", err.Error())
		}
	}

	bundle.captureLogs(captureContext, reader, network.Namespace, logTasks)
	if captureContext.Err() != nil {
		bundle.fail("capture", "context-ended", captureContext.Err().Error())
	}
	manifest := bundle.manifest(network)
	if err := writeIncidentEvidenceAtomically(options.OutputDirectory, bundle.artifacts, manifest); err != nil {
		return IncidentEvidenceManifest{}, err
	}
	return manifest, nil
}

type incidentLogTask struct {
	pod       string
	container string
}

type incidentLogResult struct {
	task      incidentLogTask
	content   []byte
	truncated bool
	err       error
}

func (bundle *incidentBundle) captureLogs(ctx context.Context, reader IncidentEvidenceReader, namespace string, tasks []incidentLogTask) {
	sort.Slice(tasks, func(left, right int) bool {
		if tasks[left].pod == tasks[right].pod {
			return tasks[left].container < tasks[right].container
		}
		return tasks[left].pod < tasks[right].pod
	})
	jobs := make(chan incidentLogTask)
	results := make(chan incidentLogResult, len(tasks))
	var workers sync.WaitGroup
	for index := 0; index < bundle.options.MaxConcurrency; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				content, truncated, err := reader.ReadPodLog(ctx, namespace, task.pod, task.container, bundle.options.LogTailLines, bundle.options.MaxArtifactBytes)
				results <- incidentLogResult{task: task, content: content, truncated: truncated, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, task := range tasks {
			select {
			case jobs <- task:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	collected := make([]incidentLogResult, 0, len(tasks))
	for result := range results {
		collected = append(collected, result)
	}
	sort.Slice(collected, func(left, right int) bool {
		if collected[left].task.pod == collected[right].task.pod {
			return collected[left].task.container < collected[right].task.container
		}
		return collected[left].task.pod < collected[right].task.pod
	})
	for _, result := range collected {
		path := "logs/" + safeSegment(result.task.pod) + "/" + safeSegment(result.task.container) + ".log"
		if result.err != nil {
			bundle.fail(path, "log-read-failed", result.err.Error())
			continue
		}
		if result.truncated {
			bundle.omit(path, "log-byte-limit", fmt.Sprintf("log was truncated at %d bytes", bundle.options.MaxArtifactBytes))
		}
		if err := bundle.add(path, "text/plain; charset=utf-8", "pod-log-tail", result.content); err != nil {
			bundle.fail(path, "artifact-rejected", err.Error())
		}
	}
}

func normalizeIncidentEvidenceOptions(options IncidentEvidenceOptions) (IncidentEvidenceOptions, error) {
	if options.Namespace == "" || options.NetworkName == "" || options.OutputDirectory == "" {
		return options, errors.New("namespace, network name, and output directory are required")
	}
	if options.Timeout == 0 {
		options.Timeout = 2 * time.Minute
	}
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = 4
	}
	if options.MaxArtifacts == 0 {
		options.MaxArtifacts = 512
	}
	if options.MaxArtifactBytes == 0 {
		options.MaxArtifactBytes = 2 << 20
	}
	if options.MaxTotalBytes == 0 {
		options.MaxTotalBytes = 64 << 20
	}
	if options.MaxOwnedResources == 0 {
		options.MaxOwnedResources = 256
	}
	if options.MaxEvents == 0 {
		options.MaxEvents = 1000
	}
	if options.LogTailLines == 0 {
		options.LogTailLines = 1000
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Timeout < time.Second || options.Timeout > 15*time.Minute || options.MaxConcurrency < 1 || options.MaxConcurrency > 16 || options.MaxArtifacts < 4 || options.MaxArtifacts > 4096 || options.MaxArtifactBytes < 1024 || options.MaxArtifactBytes > 16<<20 || options.MaxTotalBytes < options.MaxArtifactBytes || options.MaxTotalBytes > 512<<20 || options.MaxOwnedResources < 1 || options.MaxOwnedResources > 2048 || options.MaxEvents < 1 || options.MaxEvents > 10000 || options.LogTailLines < 1 || options.LogTailLines > 100000 {
		return options, errors.New("incident evidence bounds are outside supported limits")
	}
	return options, nil
}

func (bundle *incidentBundle) addJSON(path, source string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return bundle.add(path, "application/json", source, append(encoded, '\n'))
}

func (bundle *incidentBundle) add(path, mediaType, source string, content []byte) error {
	if len(bundle.artifacts) >= bundle.options.MaxArtifacts {
		bundle.omit(path, "artifact-count-limit", fmt.Sprintf("maximum is %d", bundle.options.MaxArtifacts))
		return nil
	}
	if _, duplicate := bundle.paths[path]; duplicate {
		return fmt.Errorf("duplicate artifact path %s", path)
	}
	if int64(len(content)) > bundle.options.MaxArtifactBytes {
		bundle.omit(path, "artifact-byte-limit", fmt.Sprintf("artifact has %d bytes; maximum is %d", len(content), bundle.options.MaxArtifactBytes))
		return nil
	}
	if bundle.total+int64(len(content)) > bundle.options.MaxTotalBytes {
		bundle.omit(path, "bundle-byte-limit", fmt.Sprintf("bundle maximum is %d bytes", bundle.options.MaxTotalBytes))
		return nil
	}
	digest := sha256.Sum256(content)
	bundle.paths[path] = struct{}{}
	bundle.total += int64(len(content))
	bundle.artifacts = append(bundle.artifacts, incidentArtifact{metadata: IncidentEvidenceArtifact{
		Path: path, MediaType: mediaType, SHA256: "sha256:" + hex.EncodeToString(digest[:]), Bytes: int64(len(content)), Source: source,
	}, content: append([]byte(nil), content...)})
	return nil
}

func (bundle *incidentBundle) omit(scope, reason, detail string) {
	bundle.omissions = append(bundle.omissions, incidentProblem(scope, reason, detail))
}

func (bundle *incidentBundle) fail(scope, reason, detail string) {
	bundle.errors = append(bundle.errors, incidentProblem(scope, reason, detail))
}

func incidentProblem(scope, reason, detail string) IncidentEvidenceProblem {
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	return IncidentEvidenceProblem{Scope: scope, Reason: reason, Detail: detail}
}

func (bundle *incidentBundle) manifest(network *attacknetv1beta1.StacksNetwork) IncidentEvidenceManifest {
	sort.Slice(bundle.artifacts, func(left, right int) bool {
		return bundle.artifacts[left].metadata.Path < bundle.artifacts[right].metadata.Path
	})
	sortProblems(bundle.omissions)
	sortProblems(bundle.errors)
	artifacts := make([]IncidentEvidenceArtifact, len(bundle.artifacts))
	for index := range bundle.artifacts {
		artifacts[index] = bundle.artifacts[index].metadata
	}
	return IncidentEvidenceManifest{
		SchemaVersion: "stacks-attacknet-incident-evidence/v1", CapturedAt: bundle.options.Now().UTC(),
		Network:   IncidentNetworkIdentity{Namespace: network.Namespace, Name: network.Name, UID: network.UID, Generation: network.Generation, ObservedGeneration: network.Status.ObservedGeneration, InventoryReady: network.Status.InventoryReady, InventoryDigest: network.Status.InventoryDigest},
		Bounds:    IncidentEvidenceBounds{TimeoutSeconds: int64(bundle.options.Timeout / time.Second), MaxConcurrency: bundle.options.MaxConcurrency, MaxArtifacts: bundle.options.MaxArtifacts, MaxArtifactBytes: bundle.options.MaxArtifactBytes, MaxTotalBytes: bundle.options.MaxTotalBytes, MaxOwnedResources: bundle.options.MaxOwnedResources, MaxEvents: bundle.options.MaxEvents, LogTailLines: bundle.options.LogTailLines},
		Artifacts: artifacts, Omissions: append([]IncidentEvidenceProblem(nil), bundle.omissions...), Errors: append([]IncidentEvidenceProblem(nil), bundle.errors...),
	}
}

func sortProblems(values []IncidentEvidenceProblem) {
	sort.Slice(values, func(left, right int) bool {
		if values[left].Scope == values[right].Scope {
			return values[left].Reason < values[right].Reason
		}
		return values[left].Scope < values[right].Scope
	})
}

func resourceArtifactPath(resource *unstructured.Unstructured) string {
	return "resources/" + strings.ToLower(safeSegment(resource.GetKind())) + "/" + safeSegment(resource.GetName()) + ".json"
}

func safeSegment(value string) string {
	value = filepath.Base(value)
	value = strings.ReplaceAll(value, "..", "_")
	value = strings.ReplaceAll(value, string(filepath.Separator), "_")
	if value == "" || value == "." {
		return "unknown"
	}
	return value
}

func writeIncidentEvidenceAtomically(output string, artifacts []incidentArtifact, manifest IncidentEvidenceManifest) error {
	parent := filepath.Dir(output)
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		return fmt.Errorf("incident evidence parent directory is unavailable: %s", parent)
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("incident evidence output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect incident evidence output: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".attacknet-incident-*")
	if err != nil {
		return fmt.Errorf("create temporary incident bundle: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return fmt.Errorf("secure temporary incident bundle: %w", err)
	}
	for _, artifact := range artifacts {
		path := filepath.Join(temporary, filepath.FromSlash(artifact.metadata.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create incident artifact directory: %w", err)
		}
		if err := os.WriteFile(path, artifact.content, 0o600); err != nil {
			return fmt.Errorf("write incident artifact %s: %w", artifact.metadata.Path, err)
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode incident manifest: %w", err)
	}
	total := int64(len(encoded) + 1)
	for _, artifact := range artifacts {
		total += int64(len(artifact.content))
	}
	if total > manifest.Bounds.MaxTotalBytes {
		return fmt.Errorf("incident evidence bundle including manifest has %d bytes; maximum is %d", total, manifest.Bounds.MaxTotalBytes)
	}
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write incident manifest: %w", err)
	}
	if err := os.Rename(temporary, output); err != nil {
		return fmt.Errorf("publish incident evidence bundle: %w", err)
	}
	return nil
}
