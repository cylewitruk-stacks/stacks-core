package attacknetcli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

// EvidenceSnapshot is a bounded read-only resource snapshot. It does not claim
// to be a complete incident or runtime evidence bundle.
type EvidenceSnapshot struct {
	SchemaVersion  string         `json:"schemaVersion"`
	CapturedAt     time.Time      `json:"capturedAt"`
	Scope          string         `json:"scope"`
	ResourceDigest string         `json:"resourceDigest"`
	Source         EvidenceSource `json:"source"`
	Resource       map[string]any `json:"resource"`
	Limitations    []string       `json:"limitations"`
}

// EvidenceSource binds a snapshot to one observed Kubernetes identity.
type EvidenceSource struct {
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	Generation      int64  `json:"generation"`
}

// BuildEvidenceSnapshot creates a digest-bound read-only resource artifact.
func BuildEvidenceSnapshot(object *unstructured.Unstructured, now time.Time) (EvidenceSnapshot, error) {
	if object == nil {
		return EvidenceSnapshot{}, fmt.Errorf("resource is required")
	}
	digest, err := canonical.ArtifactDigest(object.Object)
	if err != nil {
		return EvidenceSnapshot{}, fmt.Errorf("digest resource: %w", err)
	}
	return EvidenceSnapshot{
		SchemaVersion:  "stacks-attacknet-resource-snapshot/v1",
		CapturedAt:     now.UTC(),
		Scope:          "single-resource-status",
		ResourceDigest: digest,
		Source: EvidenceSource{
			APIVersion: object.GetAPIVersion(), Kind: object.GetKind(),
			Namespace: object.GetNamespace(), Name: object.GetName(),
			UID: string(object.GetUID()), ResourceVersion: object.GetResourceVersion(),
			Generation: object.GetGeneration(),
		},
		Resource: object.DeepCopy().Object,
		Limitations: []string{
			"This artifact captures one Kubernetes resource and controller status only.",
			"It is not an incident bundle and does not independently prove runtime effects.",
		},
	}, nil
}

// WriteEvidenceSnapshot writes one artifact atomically with private default
// permissions. The parent directory must already exist.
func WriteEvidenceSnapshot(path string, snapshot EvidenceSnapshot) error {
	if path == "" {
		return fmt.Errorf("evidence output path is required")
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("inspect evidence output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("evidence output parent is not a directory: %s", directory)
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence snapshot: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".attacknet-evidence-*")
	if err != nil {
		return fmt.Errorf("create temporary evidence artifact: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary evidence artifact: %w", err)
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary evidence artifact: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary evidence artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary evidence artifact: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("publish evidence artifact: %w", err)
	}
	return nil
}
