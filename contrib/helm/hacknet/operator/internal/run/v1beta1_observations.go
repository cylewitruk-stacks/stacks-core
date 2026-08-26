package run

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/protocolobservation"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/trigger"
)

// ObservationSnapshot contains controller-owned external observations. Child
// campaign transitions are assembled by the run reconciler and cannot be
// supplied by an actor.
type ObservationSnapshot struct {
	BurnHeight   *trigger.HeightObservation
	StacksHeight *trigger.HeightObservation
	Observations []trigger.Observation
	Protocol     protocolobservation.Snapshot
}

// ObservationReader supplies trusted chain and invariant observations without
// coupling scheduling policy to one telemetry implementation.
type ObservationReader interface {
	Read(context.Context, *attacknetv1beta1.AttacknetRun, *attacknetv1beta1.StacksNetwork) (ObservationSnapshot, error)
}

// KubernetesObservationReader joins controller-owned BurnchainPolicy status
// with finite, identity-bound actor protocol observations.
type KubernetesObservationReader struct {
	Reader   client.Reader
	Protocol *protocolobservation.Reader
}

// Read returns controller-owned burn height and identity-bound protocol
// observations collected through the shared finite metrics bridge.
func (r *KubernetesObservationReader) Read(ctx context.Context, run *attacknetv1beta1.AttacknetRun, network *attacknetv1beta1.StacksNetwork) (ObservationSnapshot, error) {
	if r == nil || r.Reader == nil || r.Protocol == nil {
		return ObservationSnapshot{}, errors.New("trusted observation reader requires an uncached Kubernetes API reader")
	}
	height, err := trigger.ReadBurnchainHeight(ctx, r.Reader, run.Namespace, network)
	if err != nil {
		return ObservationSnapshot{}, err
	}
	snapshot, err := r.Protocol.Read(ctx, network)
	if err != nil {
		return ObservationSnapshot{
			BurnHeight: height,
			Protocol:   protocolobservation.Snapshot{UnavailableReason: protocolobservation.UnavailableIdentity},
		}, nil
	}
	derived, err := protocolobservation.Derive(snapshot)
	if err != nil {
		return ObservationSnapshot{}, err
	}
	return ObservationSnapshot{
		BurnHeight: height, StacksHeight: derived.StacksHeight,
		Observations: derived.Observations, Protocol: snapshot,
	}, nil
}

func childDependencyObservations(children []attacknetv1beta1.FaultCampaign) []trigger.DependencyObservation {
	result := make([]trigger.DependencyObservation, 0, len(children))
	for index := range children {
		child := &children[index]
		executionID := child.Annotations[betaExecutionAnnotation]
		if executionID == "" {
			continue
		}
		source := trigger.Source{Kind: "FaultCampaign", Namespace: child.Namespace, Name: child.Name, UID: string(child.UID), ResourceVersion: child.ResourceVersion, Trusted: true}
		observation := trigger.DependencyObservation{ID: executionID, Source: source}
		startedAt := child.CreationTimestamp.Time.UTC()
		if startedAt.IsZero() {
			startedAt = time.Unix(0, 0).UTC()
		}
		if at, ok := childInjectedAt(child); ok {
			observation.Transitions = append(observation.Transitions, trigger.DependencyTransition{State: trigger.DependencyInjected, ReachedAt: at})
		}
		if at, ok := childEffectiveAt(child); ok {
			observation.Transitions = append(observation.Transitions, trigger.DependencyTransition{State: trigger.DependencyEffective, ReachedAt: at})
		}
		if child.Status.Cleanup != nil && child.Status.Cleanup.AllRecovered {
			observation.Transitions = append(observation.Transitions, trigger.DependencyTransition{State: trigger.DependencyRecovered, ReachedAt: child.Status.Cleanup.ObservedAt.Time.UTC()})
		}
		if betaTerminal(child.Status.Phase) {
			completedAt := startedAt
			if child.Status.CompletedAt != nil {
				completedAt = child.Status.CompletedAt.Time.UTC()
			}
			observation.Transitions = append(observation.Transitions, trigger.DependencyTransition{State: trigger.DependencyTerminal, ReachedAt: completedAt})
		}
		result = append(result, observation)
	}
	return result
}

func childInjectedAt(child *attacknetv1beta1.FaultCampaign) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, stage := range child.Status.Stages {
		for _, action := range stage.Actions {
			if action.Mutation == nil || action.Mutation.InjectedAt == nil {
				continue
			}
			at := action.Mutation.InjectedAt.Time.UTC()
			if at.After(latest) {
				latest = at
			}
			found = true
		}
	}
	return latest, found
}

func childEffectiveAt(child *attacknetv1beta1.FaultCampaign) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, stage := range child.Status.Stages {
		for _, result := range stage.EffectResults {
			var value struct {
				Passed     bool      `json:"passed"`
				Outcome    string    `json:"outcome"`
				ObservedAt time.Time `json:"observedAt"`
			}
			if json.Unmarshal(result.Raw, &value) == nil && (value.Passed || value.Outcome == "Proven") {
				if value.ObservedAt.After(latest) {
					latest = value.ObservedAt.UTC()
				}
				found = true
			}
		}
	}
	return latest, found
}
