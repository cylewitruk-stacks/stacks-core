package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

type terminalRunDecision struct {
	Child    string          `json:"child"`
	ChildUID string          `json:"childUid"`
	Phase    string          `json:"phase"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

// captureTerminalRun retains the exact terminal scheduler and child state that
// produced a bounded result without duplicating large evidence in CR status.
func (runtimeBoundary *KubernetesFuzzRuntime) captureTerminalRun(
	ctx context.Context, attempt fuzzsession.ObservedAttempt,
) ([]fuzzsession.Artifact, error) {
	if runtimeBoundary.Backend == nil || attempt.Run.Name == "" || attempt.Run.UID == "" {
		return nil, errors.New("terminal run evidence requires an exact admitted run identity")
	}
	kind, err := LookupKind("AttacknetRun")
	if err != nil {
		return nil, err
	}
	run, err := runtimeBoundary.Backend.Get(ctx, ResourceRef{
		Kind: kind, Namespace: attempt.Run.Namespace, Name: attempt.Run.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("read terminal AttacknetRun: %w", err)
	}
	if string(run.GetUID()) != attempt.Run.UID || run.GetGeneration() != attempt.Run.Generation {
		return nil, errors.New("terminal AttacknetRun identity changed before evidence capture")
	}
	for path, expected := range map[string]string{
		"phase": attempt.Result.Phase, "reason": attempt.Result.Reason,
		"attribution": attempt.Result.Attribution,
	} {
		observed, found, nestedErr := unstructured.NestedString(run.Object, "status", path)
		if nestedErr != nil || !found || observed != expected {
			return nil, fmt.Errorf("terminal AttacknetRun %s does not match observed result", path)
		}
	}
	return runtimeBoundary.captureTerminalObjects(ctx, run)
}

func (runtimeBoundary *KubernetesFuzzRuntime) captureTerminalObjects(
	ctx context.Context, run *unstructured.Unstructured,
) ([]fuzzsession.Artifact, error) {
	runArtifact, err := terminalObjectArtifact("control/attacknetrun.json", run)
	if err != nil {
		return nil, fmt.Errorf("encode terminal AttacknetRun evidence: %w", err)
	}
	artifacts := []fuzzsession.Artifact{runArtifact}
	decisions, found, err := unstructured.NestedSlice(run.Object, "status", "decisions")
	if err != nil {
		return nil, fmt.Errorf("read terminal AttacknetRun decisions: %w", err)
	}
	if !found {
		return artifacts, nil
	}
	seen := make(map[string]struct{}, len(decisions))
	for _, raw := range decisions {
		decision, err := decodeTerminalRunDecision(raw)
		if err != nil {
			return nil, err
		}
		childKind, err := terminalChildKind(decision)
		if err != nil {
			return nil, err
		}
		key := childKind + "/" + decision.Child
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("terminal AttacknetRun repeats child %s", key)
		}
		seen[key] = struct{}{}
		artifact, err := runtimeBoundary.captureTerminalChild(ctx, run, decision, childKind)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func decodeTerminalRunDecision(raw any) (terminalRunDecision, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return terminalRunDecision{}, fmt.Errorf("encode terminal child decision: %w", err)
	}
	var decision terminalRunDecision
	if json.Unmarshal(encoded, &decision) != nil ||
		decision.Child == "" || decision.ChildUID == "" || decision.Phase == "" {
		return terminalRunDecision{}, errors.New("terminal AttacknetRun contains an incomplete child decision")
	}
	return decision, nil
}

func terminalChildKind(decision terminalRunDecision) (string, error) {
	if len(decision.Evidence) == 0 {
		return "FaultCampaign", nil
	}
	var tagged struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(decision.Evidence, &tagged) != nil ||
		(tagged.Kind != "FaultCampaign" && tagged.Kind != "UpgradeCampaign") {
		return "", errors.New("terminal AttacknetRun contains unsupported child evidence")
	}
	return tagged.Kind, nil
}

func (runtimeBoundary *KubernetesFuzzRuntime) captureTerminalChild(
	ctx context.Context, run *unstructured.Unstructured, decision terminalRunDecision, childKind string,
) (fuzzsession.Artifact, error) {
	kind, err := LookupKind(childKind)
	if err != nil {
		return fuzzsession.Artifact{}, err
	}
	child, err := runtimeBoundary.Backend.Get(ctx, ResourceRef{
		Kind: kind, Namespace: run.GetNamespace(), Name: decision.Child,
	})
	if err != nil {
		return fuzzsession.Artifact{}, fmt.Errorf("read terminal %s %s: %w", childKind, decision.Child, err)
	}
	owner := metav1.GetControllerOf(child)
	phase, found, phaseErr := unstructured.NestedString(child.Object, "status", "phase")
	if string(child.GetUID()) != decision.ChildUID || owner == nil || owner.UID != run.GetUID() ||
		owner.Name != run.GetName() || owner.APIVersion != run.GetAPIVersion() || owner.Kind != run.GetKind() ||
		phaseErr != nil || !found || phase != decision.Phase {
		return fuzzsession.Artifact{}, fmt.Errorf("terminal %s %s does not match its durable decision", childKind, decision.Child)
	}
	artifact, err := terminalObjectArtifact(
		fmt.Sprintf("control/%ss/%s.json", strings.ToLower(childKind), decision.Child), child,
	)
	if err != nil {
		return fuzzsession.Artifact{}, fmt.Errorf("encode terminal %s %s: %w", childKind, decision.Child, err)
	}
	return artifact, nil
}

func terminalObjectArtifact(name string, object *unstructured.Unstructured) (fuzzsession.Artifact, error) {
	snapshot := object.DeepCopy()
	snapshot.SetManagedFields(nil)
	encoded, err := json.Marshal(snapshot.Object)
	if err != nil {
		return fuzzsession.Artifact{}, err
	}
	return fuzzsession.Artifact{Name: name, ContentType: "application/json", Data: encoded}, nil
}
