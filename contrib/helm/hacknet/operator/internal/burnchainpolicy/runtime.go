// Package burnchainpolicy reconciles externally controlled Bitcoin regtest clocks.
package burnchainpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

const (
	policyKey                 = "policy.env"
	annotationRuntimeGen      = "testing.stacks.org/runtime-policy-generation"
	annotationPolicyDigest    = "testing.stacks.org/runtime-policy-digest"
	annotationFlashID         = "testing.stacks.org/flash-id"
	labelManagedBy            = "testing.stacks.org/managed-by"
	labelManagedByValue       = "stacks-burnchain-policy-controller"
	labelNetwork              = "testing.stacks.org/network"
	labelPolicy               = "testing.stacks.org/burnchain-policy"
	labelComponent            = "app.kubernetes.io/component"
	componentClock            = "burnchain-clock"
	clockHealthPort           = int32(18500)
	maximumRuntimeDelay       = uint64(3600)
	maximumBootstrapHeight    = int64(10_000_000)
	maximumFlashBlocks        = int32(10_000)
	maximumDestinationEntries = 64
)

var (
	boundedName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	secretKey   = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

type desiredRuntime struct {
	policy    burnchain.Policy
	encoded   string
	digest    string
	flashID   string
	flashDone bool
}

func compileRuntime(policy *attacknetv1beta1.BurnchainPolicy, current *corev1.ConfigMap, observed *burnchain.Status) (desiredRuntime, error) {
	if err := validatePolicy(policy); err != nil {
		return desiredRuntime{}, err
	}
	mode := burnchain.ModeRun
	if policy.Spec.Paused {
		mode = burnchain.ModePause
	}
	interval := uint64(policy.Spec.Cadence.Duration / time.Second)
	selection := policy.Spec.DestinationSelection
	if selection == "" {
		selection = attacknetv1beta1.BurnchainDestinationRoundRobin
	}
	addressMode := burnchain.AddressRoundRobin
	if selection == attacknetv1beta1.BurnchainDestinationFixed {
		addressMode = burnchain.AddressFixed
	}
	runtimePolicy := burnchain.Policy{
		Mode: mode, IntervalSeconds: interval, AddressMode: addressMode,
		FixedAddressIndex: uint64(policy.Spec.FixedDestinationIndex),
	}
	flashPending := policy.Spec.Flash != nil && policy.Spec.Flash.ID != policy.Status.AppliedFlashID
	flashID := ""
	if flashPending {
		flashID = policy.Spec.Flash.ID
		// A flash is a bounded target-height request. Keep ordinary cadence
		// paused until the controller observes completion, then restore it.
		runtimePolicy.Mode = burnchain.ModePause
		if policy.Spec.Flash.Interval.Duration > 0 {
			runtimePolicy.IntervalSeconds = uint64(policy.Spec.Flash.Interval.Duration / time.Second)
		}
		if current != nil && current.Annotations[annotationFlashID] == flashID {
			if existing, err := parseRuntime(current); err == nil {
				runtimePolicy.BurstTargetHeight = existing.BurstTargetHeight
			}
		}
		if runtimePolicy.BurstTargetHeight == 0 && observed != nil && observed.BitcoinHeight != nil {
			runtimePolicy.BurstTargetHeight = *observed.BitcoinHeight + uint64(policy.Spec.Flash.Blocks)
		}
		if runtimePolicy.BurstTargetHeight == 0 {
			// Hold the clock while waiting for its post-bootstrap height. A raw
			// block count would replay after a Pod restart; only a target is safe.
			runtimePolicy.Mode = burnchain.ModePause
		}
	}
	currentGeneration := uint64(0)
	var currentPolicy burnchain.Policy
	currentValid := false
	if current != nil {
		currentGeneration, _ = strconv.ParseUint(current.Annotations[annotationRuntimeGen], 10, 64)
		if parsed, err := parseRuntime(current); err == nil {
			currentPolicy, currentValid = parsed, true
			if currentGeneration < parsed.Generation {
				currentGeneration = parsed.Generation
			}
		}
	}
	runtimePolicy.Generation = currentGeneration
	if !currentValid || !sameRuntimePolicy(currentPolicy, runtimePolicy) {
		if currentGeneration == ^uint64(0) {
			return desiredRuntime{}, fmt.Errorf("runtime policy generation exhausted")
		}
		runtimePolicy.Generation++
		if runtimePolicy.Generation == 0 {
			runtimePolicy.Generation = 1
		}
	}
	encoded := burnchain.EncodePolicy(runtimePolicy)
	digestBytes := sha256.Sum256([]byte(encoded))
	flashDone := flashPending && runtimePolicy.BurstTargetHeight > 0 && observed != nil && observed.BitcoinHeight != nil && *observed.BitcoinHeight >= runtimePolicy.BurstTargetHeight
	return desiredRuntime{policy: runtimePolicy, encoded: encoded, digest: "sha256:" + hex.EncodeToString(digestBytes[:]), flashID: flashID, flashDone: flashDone}, nil
}

func validatePolicy(policy *attacknetv1beta1.BurnchainPolicy) error {
	if len(policy.Spec.NetworkRef) > 63 || len(policy.Spec.BitcoinNodeRef) > 63 || !boundedName.MatchString(policy.Spec.NetworkRef) || !boundedName.MatchString(policy.Spec.BitcoinNodeRef) {
		return fmt.Errorf("networkRef and bitcoinNodeRef must be DNS-1123 names")
	}
	if policy.Spec.BootstrapHeight < 0 || policy.Spec.BootstrapHeight > maximumBootstrapHeight {
		return fmt.Errorf("bootstrapHeight must be from 0 through %d", maximumBootstrapHeight)
	}
	if err := validateWholeSeconds("cadence", policy.Spec.Cadence.Duration, true, maximumRuntimeDelay); err != nil {
		return err
	}
	if len(policy.Spec.Destinations) == 0 || len(policy.Spec.Destinations) > maximumDestinationEntries {
		return fmt.Errorf("destinations must contain from 1 through %d entries", maximumDestinationEntries)
	}
	wallets, addresses := map[string]bool{}, map[string]bool{}
	for index, destination := range policy.Spec.Destinations {
		if destination.WalletName == "" || destination.Address == "" || len(destination.WalletName) > 128 || len(destination.Address) > 128 || strings.ContainsAny(destination.WalletName+destination.Address, ",\r\n") {
			return fmt.Errorf("destination %d must contain non-empty comma-free walletName and address", index)
		}
		if wallets[destination.WalletName] || addresses[destination.Address] {
			return fmt.Errorf("destination %d duplicates a wallet or address", index)
		}
		wallets[destination.WalletName], addresses[destination.Address] = true, true
	}
	selection := policy.Spec.DestinationSelection
	if selection == "" {
		selection = attacknetv1beta1.BurnchainDestinationRoundRobin
	}
	if selection != attacknetv1beta1.BurnchainDestinationRoundRobin && selection != attacknetv1beta1.BurnchainDestinationFixed {
		return fmt.Errorf("unsupported destinationSelection %q", selection)
	}
	if selection == attacknetv1beta1.BurnchainDestinationFixed {
		if policy.Spec.FixedDestinationIndex < 0 || int(policy.Spec.FixedDestinationIndex) >= len(policy.Spec.Destinations) {
			return fmt.Errorf("fixedDestinationIndex is outside destinations")
		}
	} else if policy.Spec.FixedDestinationIndex != 0 {
		return fmt.Errorf("fixedDestinationIndex requires destinationSelection=fixed")
	}
	if policy.Spec.Flash != nil {
		if !boundedName.MatchString(policy.Spec.Flash.ID) || len(policy.Spec.Flash.ID) > 63 {
			return fmt.Errorf("flash.id must be a DNS-1123 name")
		}
		if policy.Spec.Flash.Blocks <= 0 || policy.Spec.Flash.Blocks > maximumFlashBlocks {
			return fmt.Errorf("flash.blocks must be from 1 through %d", maximumFlashBlocks)
		}
		if err := validateWholeSeconds("flash.interval", policy.Spec.Flash.Interval.Duration, true, maximumRuntimeDelay); err != nil {
			return err
		}
	}
	if schedule := policy.Spec.ProtocolSchedule; schedule != nil {
		if len(schedule.Epochs) == 0 || schedule.RewardCycle == nil {
			return fmt.Errorf("protocolSchedule must declare both epoch and reward-cycle geometry")
		}
		names, heights := map[string]bool{}, map[int64]bool{}
		for index, epoch := range schedule.Epochs {
			if epoch.Name == "" || len(epoch.Name) > 63 || epoch.StartHeight < 0 || epoch.StartHeight > maximumBootstrapHeight {
				return fmt.Errorf("protocolSchedule epoch %d has an invalid name or startHeight", index)
			}
			if names[epoch.Name] || heights[epoch.StartHeight] {
				return fmt.Errorf("protocolSchedule epoch %d duplicates a name or startHeight", index)
			}
			names[epoch.Name], heights[epoch.StartHeight] = true, true
		}
		if reward := schedule.RewardCycle; reward != nil {
			if reward.FirstHeight < 0 || reward.FirstHeight > maximumBootstrapHeight || reward.CycleLength < 1 || reward.CycleLength > 1_000_000 || reward.PrepareLength < 0 || reward.PrepareLength >= reward.CycleLength {
				return fmt.Errorf("protocolSchedule.rewardCycle has invalid geometry")
			}
		}
	}
	for name, value := range map[string]time.Duration{
		"rpc.timeout": policy.Spec.RPC.Timeout.Duration, "rpc.minimumBackoff": policy.Spec.RPC.MinimumBackoff.Duration,
		"rpc.maximumBackoff": policy.Spec.RPC.MaximumBackoff.Duration,
	} {
		if value != 0 {
			if err := validateWholeSeconds(name, value, false, 300); err != nil {
				return err
			}
		}
	}
	minimum, maximum := policy.Spec.RPC.MinimumBackoff.Duration, policy.Spec.RPC.MaximumBackoff.Duration
	if minimum > 0 && maximum > 0 && maximum < minimum {
		return fmt.Errorf("rpc.maximumBackoff must not be less than rpc.minimumBackoff")
	}
	username, password := policy.Spec.RPC.UsernameSecretRef, policy.Spec.RPC.PasswordSecretRef
	if (username == nil) != (password == nil) {
		return fmt.Errorf("rpc usernameSecretRef and passwordSecretRef must be configured together")
	}
	if username != nil {
		if len(username.Name) > 63 || len(password.Name) > 63 || len(username.Key) > 253 || len(password.Key) > 253 || !boundedName.MatchString(username.Name) || !secretKey.MatchString(username.Key) || !boundedName.MatchString(password.Name) || !secretKey.MatchString(password.Key) {
			return fmt.Errorf("rpc credential Secret references require DNS-1123 names and non-empty keys")
		}
	}
	return nil
}

func validateWholeSeconds(name string, value time.Duration, allowZero bool, maximum uint64) error {
	minimum := 1
	if allowZero {
		minimum = 0
	}
	if value < 0 || (!allowZero && value == 0) || value%time.Second != 0 || uint64(value/time.Second) > maximum {
		return fmt.Errorf("%s must be whole seconds from %d through %d", name, minimum, maximum)
	}
	return nil
}

func parseRuntime(configMap *corev1.ConfigMap) (burnchain.Policy, error) {
	return burnchain.ParsePolicy(strings.NewReader(configMap.Data[policyKey]), burnchain.PolicyDefaults{IntervalSeconds: 60, MaxDelaySeconds: maximumRuntimeDelay})
}

func sameRuntimePolicy(left, right burnchain.Policy) bool {
	left.Generation, right.Generation = 0, 0
	return left == right
}

func deterministicSeed(uid string) uint64 {
	digest := sha256.Sum256([]byte(uid))
	return binary.BigEndian.Uint64(digest[:8])
}

func condition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, ObservedGeneration: generation}
}
