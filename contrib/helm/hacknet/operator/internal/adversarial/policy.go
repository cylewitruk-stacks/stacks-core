// Package adversarial validates and normalizes testing-only actor policies.
package adversarial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const (
	// ProfileV1 is the first testing-only signer policy contract.
	ProfileV1 = "stacks-signer-testing/v1"
	// AlgorithmV1 identifies the deterministic selector semantics.
	AlgorithmV1 = "stacks-signer-adversarial-selector/v1"
	// SessionSchemaV1 identifies the controller-owned activation document.
	SessionSchemaV1 = "stacks-attacknet-signer-behavior-session/v1"
	// SessionAnnotation carries one bounded activation document on a signer Pod.
	SessionAnnotation = "testing.stacks.org/adversarial-session"
	// SessionMountPath is the read-only Downward API directory in testing signers.
	SessionMountPath = "/run/attacknet-signer"
	// SessionFilePath is the atomically updated activation document.
	SessionFilePath = SessionMountPath + "/session.json"
)

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hashPrefixPattern = regexp.MustCompile(`^[0-9a-f]{2,32}$`)
)

// ObserverName returns the bounded logical actor name paired with a signer.
func ObserverName(signer string) string {
	candidate := signer + "-observer"
	if len(candidate) <= 40 {
		return candidate
	}
	digest := sha256.Sum256([]byte(candidate))
	return strings.TrimRight(signer[:30], "-") + "-" + hex.EncodeToString(digest[:4])
}

// Policy is the canonical document injected into a testing-only signer.
type Policy struct {
	Algorithm      string   `json:"algorithm"`
	Behavior       string   `json:"behavior"`
	DelayMillis    int64    `json:"delayMillis,omitempty"`
	MaxEvaluations int32    `json:"maxEvaluations"`
	MaxMatches     int32    `json:"maxMatches"`
	PatchDigest    string   `json:"patchDigest"`
	Profile        string   `json:"profile"`
	Selector       Selector `json:"selector"`
}

// Selector is the normalized, conjunctive proposal selector.
type Selector struct {
	EveryNth           int32  `json:"everyNth,omitempty"`
	MaxStacksHeight    *int64 `json:"maxStacksHeight,omitempty"`
	MinStacksHeight    *int64 `json:"minStacksHeight,omitempty"`
	ProposalHashPrefix string `json:"proposalHashPrefix,omitempty"`
	SeedOffset         int32  `json:"seedOffset,omitempty"`
}

// Decision is one deterministic selector evaluation.
type Decision struct {
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
	Ordinal int64  `json:"ordinal"`
}

// Normalize validates and converts the Kubernetes API to the signer contract.
func Normalize(value *attacknetv1beta1.AdversarialSignerPolicy) (Policy, error) {
	if value == nil {
		return Policy{}, errors.New("adversarial policy is required")
	}
	if value.Profile != ProfileV1 {
		return Policy{}, fmt.Errorf("unsupported adversarial profile %q", value.Profile)
	}
	if !digestPattern.MatchString(value.PatchDigest) {
		return Policy{}, errors.New("adversarial patchDigest must be a lowercase sha256 digest")
	}
	if value.MaxMatches < 1 || value.MaxMatches > 1024 {
		return Policy{}, errors.New("adversarial maxMatches must be within 1..1024")
	}
	if value.MaxEvaluations < value.MaxMatches || value.MaxEvaluations > 65_536 {
		return Policy{}, errors.New("adversarial maxEvaluations must be within maxMatches..65536")
	}
	if value.Observer.Image == "" {
		return Policy{}, errors.New("adversarial observer.image is required")
	}
	if err := validateEgress(value.Egress); err != nil {
		return Policy{}, err
	}
	selector, err := normalizeSelector(value.Selector)
	if err != nil {
		return Policy{}, err
	}
	policy := Policy{
		Algorithm: AlgorithmV1, Behavior: value.Behavior,
		MaxEvaluations: value.MaxEvaluations, MaxMatches: value.MaxMatches, PatchDigest: value.PatchDigest,
		Profile: value.Profile, Selector: selector,
	}
	switch value.Behavior {
	case "withhold":
		if value.Delay != nil {
			return Policy{}, errors.New("withhold behavior must not specify delay")
		}
	case "delay":
		if value.Delay == nil || value.Delay.Duration < time.Millisecond || value.Delay.Duration > 120*time.Second {
			return Policy{}, errors.New("delay behavior requires delay within 1ms..120s")
		}
		if value.Delay.Duration%time.Millisecond != 0 {
			return Policy{}, errors.New("delay must be an exact number of milliseconds")
		}
		policy.DelayMillis = value.Delay.Milliseconds()
	case "suppress-peer-responses":
		if value.Delay != nil {
			return Policy{}, errors.New("suppress-peer-responses must not specify delay")
		}
		if selector.MinStacksHeight != nil || selector.MaxStacksHeight != nil || selector.EveryNth != 0 || selector.SeedOffset != 0 {
			return Policy{}, errors.New("suppress-peer-responses supports only proposalHashPrefix selection")
		}
	default:
		return Policy{}, fmt.Errorf("unsupported adversarial behavior %q", value.Behavior)
	}
	return policy, nil
}

func normalizeSelector(value attacknetv1beta1.AdversarialProposalSelector) (Selector, error) {
	if value.MinStacksHeight != nil && *value.MinStacksHeight < 1 {
		return Selector{}, errors.New("minimum Stacks height must be positive")
	}
	if value.MaxStacksHeight != nil && *value.MaxStacksHeight < 1 {
		return Selector{}, errors.New("maximum Stacks height must be positive")
	}
	if value.MinStacksHeight != nil && value.MaxStacksHeight != nil && *value.MinStacksHeight > *value.MaxStacksHeight {
		return Selector{}, errors.New("minimum Stacks height cannot exceed maximum")
	}
	everyNth := int32(0)
	if value.EveryNth != nil {
		everyNth = *value.EveryNth
		if everyNth < 1 || everyNth > 1024 {
			return Selector{}, errors.New("everyNth must be within 1..1024")
		}
	}
	if value.SeedOffset < 0 || value.SeedOffset > 1023 {
		return Selector{}, errors.New("seedOffset must be within 0..1023")
	}
	if everyNth == 0 && value.SeedOffset != 0 {
		return Selector{}, errors.New("seedOffset requires everyNth")
	}
	if everyNth > 0 && value.SeedOffset >= everyNth {
		return Selector{}, errors.New("seedOffset must be less than everyNth")
	}
	prefix := strings.ToLower(value.ProposalHashPrefix)
	if prefix != "" && !hashPrefixPattern.MatchString(prefix) {
		return Selector{}, errors.New("proposalHashPrefix must contain 2..32 lowercase hexadecimal characters")
	}
	return Selector{
		EveryNth: everyNth, MinStacksHeight: copyInt64(value.MinStacksHeight),
		MaxStacksHeight:    copyInt64(value.MaxStacksHeight),
		ProposalHashPrefix: prefix, SeedOffset: value.SeedOffset,
	}, nil
}

func validateEgress(value attacknetv1beta1.AdversarialEgressSpec) error {
	switch value.Profile {
	case "restricted":
		if value.AllowUnrestricted {
			return errors.New("restricted egress must not set allowUnrestricted")
		}
	case "unrestricted":
		if !value.AllowUnrestricted {
			return errors.New("unrestricted egress requires allowUnrestricted=true")
		}
	default:
		return fmt.Errorf("unsupported adversarial egress profile %q", value.Profile)
	}
	return nil
}

// Encode returns the canonical JSON injected into the signer image.
func Encode(policy Policy) (string, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode adversarial policy: %w", err)
	}
	return string(encoded), nil
}

// Digest returns the reproducible policy digest recorded in actor identity.
func Digest(policy Policy) (string, error) {
	return canonical.Digest(policy)
}

// ResolveSigner returns the normalized policy and digest declared for one
// signer member. It is shared by topology compilation and campaign admission.
func ResolveSigner(network *attacknetv1beta1.StacksNetwork, signer string) (Policy, string, error) {
	if network == nil {
		return Policy{}, "", errors.New("StacksNetwork is required")
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			if member.Name != signer {
				continue
			}
			policy, err := Normalize(member.Adversarial)
			if err != nil {
				return Policy{}, "", fmt.Errorf("signer %q adversarial policy: %w", signer, err)
			}
			digest, err := Digest(policy)
			if err != nil {
				return Policy{}, "", err
			}
			return policy, digest, nil
		}
	}
	return Policy{}, "", fmt.Errorf("signer %q has no declared adversarial policy", signer)
}

// Evaluate applies the versioned selector to one unique proposal ordinal.
func Evaluate(policy Policy, height int64, proposalHash string, ordinal int64, matchesSoFar int32) Decision {
	if ordinal < 1 {
		return Decision{Reason: "InvalidOrdinal", Ordinal: ordinal}
	}
	if ordinal > int64(policy.MaxEvaluations) {
		return Decision{Reason: "EvaluationBudgetExhausted", Ordinal: ordinal}
	}
	selector := policy.Selector
	if selector.MinStacksHeight != nil && height < *selector.MinStacksHeight {
		return Decision{Reason: "BeforeHeightWindow", Ordinal: ordinal}
	}
	if selector.MaxStacksHeight != nil && height > *selector.MaxStacksHeight {
		return Decision{Reason: "AfterHeightWindow", Ordinal: ordinal}
	}
	if selector.ProposalHashPrefix != "" && !strings.HasPrefix(strings.ToLower(proposalHash), selector.ProposalHashPrefix) {
		return Decision{Reason: "HashPrefixMismatch", Ordinal: ordinal}
	}
	if selector.EveryNth > 0 && (ordinal+int64(selector.SeedOffset)-1)%int64(selector.EveryNth) != 0 {
		return Decision{Reason: "OrdinalMismatch", Ordinal: ordinal}
	}
	if matchesSoFar < 0 || matchesSoFar >= policy.MaxMatches {
		return Decision{Reason: "MatchBudgetExhausted", Ordinal: ordinal}
	}
	return Decision{Matched: true, Reason: "Matched", Ordinal: ordinal}
}

func copyInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
