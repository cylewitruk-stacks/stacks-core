// Package signerset resolves the canonical signer identities and weights from
// an enrolled Stacks node before a fault or run is admitted.
package signerset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const actorLabel = "testing.stacks.org/actor"

var compressedKey = regexp.MustCompile(`^(02|03)[0-9a-f]{64}$`)

const maxJSONSafeInteger = 9_007_199_254_740_991

// Result is the canonicalized manifest and its independently observed source.
type Result struct {
	WeightsByActor      map[string]float64
	HasSigners          bool
	RewardCycle         int64
	ObservedTotalWeight float64
	CanonicalThreshold  float64
	SignerSetDigest     string
	ObservedFrom        string
	WeightsMatch        bool
}

// Resolver supplies a canonical signer-set view to admission controllers.
type Resolver interface {
	Resolve(context.Context, *attacknetv1alpha1.StacksNetwork, []corev1.Pod) (Result, error)
}

// HTTPResolver reads PoX and reward-set state from a Ready enrolled Stacks node.
type HTTPResolver struct {
	Client *http.Client
}

// TransientError marks an RPC observation failure that reconciliation should retry.
type TransientError struct{ Err error }

func (e *TransientError) Error() string { return e.Err.Error() }
func (e *TransientError) Unwrap() error { return e.Err }

type rewardSetResponse struct {
	StackerSet struct {
		Signers []ObservedSigner `json:"signers"`
	} `json:"stacker_set"`
}

// ObservedSigner is one canonical reward-set identity returned by Stacks RPC.
type ObservedSigner struct {
	SigningKey string  `json:"signing_key"`
	Weight     float64 `json:"weight"`
}

type poxResponse struct {
	CurrentCycle struct {
		ID int64 `json:"id"`
	} `json:"current_cycle"`
}

type signerIdentity struct {
	SigningKey string  `json:"signingKey"`
	Weight     float64 `json:"weight"`
}

// Resolve verifies exact signer-key membership and replaces declared weights
// with the active reward cycle's canonical weights.
func (r *HTTPResolver) Resolve(ctx context.Context, network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod) (Result, error) {
	if !declaresSigners(network.Spec.Actors) {
		digest, err := canonical.ArtifactDigest([]signerIdentity{})
		if err != nil {
			return Result{}, err
		}
		return Result{
			WeightsByActor:  map[string]float64{},
			SignerSetDigest: digest,
			ObservedFrom:    "network-spec:no-signers",
			WeightsMatch:    true,
		}, nil
	}
	actor, pod, port, err := endpoint(network, pods)
	if err != nil {
		return Result{}, err
	}
	base := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, port)
	var pox poxResponse
	if err := r.getJSON(ctx, base+"/v2/pox", &pox); err != nil {
		return Result{}, &TransientError{Err: fmt.Errorf("read current reward cycle from %s: %w", actor.Name, err)}
	}
	if pox.CurrentCycle.ID < 0 {
		return Result{}, errors.New("Stacks RPC /v2/pox lacks a current reward cycle")
	}
	var response rewardSetResponse
	if err := r.getJSON(ctx, fmt.Sprintf("%s/v3/stacker_set/%d", base, pox.CurrentCycle.ID), &response); err != nil {
		return Result{}, &TransientError{Err: fmt.Errorf("read reward set from %s: %w", actor.Name, err)}
	}
	return Resolve(network.Spec.Actors, response.StackerSet.Signers, pox.CurrentCycle.ID, actor.Name)
}

// Resolve applies an already-observed reward set. It is exported for replayable
// tests and offline evidence verification.
func Resolve(actors []attacknetv1alpha1.ActorSpec, signers []ObservedSigner, rewardCycle int64, observedFrom string) (Result, error) {
	declared := map[string]attacknetv1alpha1.ActorSpec{}
	indexes := map[int32]bool{}
	for _, actor := range actors {
		if actor.SignerIndex == nil {
			continue
		}
		if actor.SignerWeight == nil || *actor.SignerWeight <= 0 || actor.SignerPublicKey == "" {
			return Result{}, fmt.Errorf("signer-bound actor %s lacks index, positive weight, or public key", actor.Name)
		}
		if !compressedKey.MatchString(actor.SignerPublicKey) {
			return Result{}, fmt.Errorf("declared signer %s has an invalid compressed secp256k1 public key", actor.Name)
		}
		if existing, ok := declared[actor.SignerPublicKey]; ok {
			if existing.SignerIndex == nil || *existing.SignerIndex != *actor.SignerIndex || *existing.SignerWeight != *actor.SignerWeight {
				return Result{}, fmt.Errorf("signer identity %s is declared inconsistently", actor.SignerPublicKey)
			}
			continue
		}
		if indexes[*actor.SignerIndex] {
			return Result{}, fmt.Errorf("duplicate declared signer index %d", *actor.SignerIndex)
		}
		indexes[*actor.SignerIndex] = true
		declared[actor.SignerPublicKey] = actor
	}
	if len(declared) == 0 {
		return Result{}, errors.New("network declares no signer identities")
	}
	if len(signers) == 0 {
		return Result{}, errors.New("reward-set response has no signers")
	}
	observed := make(map[string]float64, len(signers))
	identities := make([]signerIdentity, 0, len(signers))
	for index, signer := range signers {
		if !compressedKey.MatchString(signer.SigningKey) || signer.Weight <= 0 ||
			math.Trunc(signer.Weight) != signer.Weight || signer.Weight > maxJSONSafeInteger {
			return Result{}, fmt.Errorf("observed signer %d has an invalid key or weight", index)
		}
		if _, duplicate := observed[signer.SigningKey]; duplicate {
			return Result{}, fmt.Errorf("duplicate observed signer public key %s", signer.SigningKey)
		}
		observed[signer.SigningKey] = signer.Weight
		identities = append(identities, signerIdentity{SigningKey: signer.SigningKey, Weight: signer.Weight})
	}
	for key := range declared {
		if _, ok := observed[key]; !ok {
			return Result{}, fmt.Errorf("declared signer identity %s is absent from reward cycle %d", key, rewardCycle)
		}
	}
	for key := range observed {
		if _, ok := declared[key]; !ok {
			return Result{}, fmt.Errorf("reward cycle %d contains unexpected signer identity %s", rewardCycle, key)
		}
	}
	weightsByActor := map[string]float64{}
	weightsMatch, total := true, 0.0
	for index := range actors {
		actor := &actors[index]
		if actor.SignerIndex == nil {
			continue
		}
		if actor.SignerPublicKey == "" {
			return Result{}, fmt.Errorf("signer-bound actor %s lacks a declared signing key", actor.Name)
		}
		weight := observed[actor.SignerPublicKey]
		if actor.SignerWeight == nil || *actor.SignerWeight != weight {
			weightsMatch = false
		}
		weightsByActor[actor.Name] = weight
	}
	for _, weight := range observed {
		total += weight
		if total > maxJSONSafeInteger {
			return Result{}, errors.New("observed signer total weight exceeds the canonical JSON safe-integer range")
		}
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left].SigningKey < identities[right].SigningKey })
	digest, err := canonical.ArtifactDigest(identities)
	if err != nil {
		return Result{}, err
	}
	return Result{
		WeightsByActor:      weightsByActor,
		HasSigners:          true,
		RewardCycle:         rewardCycle,
		ObservedTotalWeight: total,
		CanonicalThreshold:  math.Ceil(total * 0.7),
		SignerSetDigest:     digest,
		ObservedFrom:        observedFrom,
		WeightsMatch:        weightsMatch,
	}, nil
}

func declaresSigners(actors []attacknetv1alpha1.ActorSpec) bool {
	for _, actor := range actors {
		if actor.Role == "signer" || actor.SignerIndex != nil || actor.SignerWeight != nil || actor.SignerPublicKey != "" {
			return true
		}
	}
	return false
}

func (r *HTTPResolver) getJSON(ctx context.Context, url string, output any) error {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, body)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func endpoint(network *attacknetv1alpha1.StacksNetwork, pods []corev1.Pod) (attacknetv1alpha1.ActorSpec, corev1.Pod, int32, error) {
	roleOrder := map[string]int{"miner": 0, "node": 1, "companion": 1, "follower": 2}
	actors := append([]attacknetv1alpha1.ActorSpec(nil), network.Spec.Actors...)
	sort.Slice(actors, func(left, right int) bool {
		leftOrder, leftOK := roleOrder[actors[left].Role]
		rightOrder, rightOK := roleOrder[actors[right].Role]
		if !leftOK {
			leftOrder = 9
		}
		if !rightOK {
			rightOrder = 9
		}
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		return actors[left].Name < actors[right].Name
	})
	for _, actor := range actors {
		if _, ok := roleOrder[actor.Role]; !ok {
			continue
		}
		port := actorRPCPort(actor)
		if port == 0 {
			continue
		}
		for _, pod := range pods {
			if pod.DeletionTimestamp == nil && pod.Labels[actorLabel] == actor.Name && pod.Status.PodIP != "" && podReady(pod) {
				return actor, pod, port, nil
			}
		}
	}
	return attacknetv1alpha1.ActorSpec{}, corev1.Pod{}, 0, errors.New("no Ready enrolled Stacks RPC endpoint is available for signer-set verification")
}

func actorRPCPort(actor attacknetv1alpha1.ActorSpec) int32 {
	for _, candidate := range actor.Ports {
		if candidate.Name != "rpc" {
			continue
		}
		if candidate.ContainerPort != 0 {
			return candidate.ContainerPort
		}
		return candidate.ServicePort
	}
	// The topology renderer supplies this role default when ports are omitted.
	// Signer-set admission must resolve the same effective actor contract.
	switch actor.Role {
	case "miner", "companion", "follower":
		return 20443
	default:
		return 0
	}
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
