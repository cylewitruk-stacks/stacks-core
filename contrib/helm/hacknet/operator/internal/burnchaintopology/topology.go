// Package burnchaintopology owns normalization and binding of the admitted
// Bitcoin P2P graph and Stacks-node follower assignments.
package burnchaintopology

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const (
	// SchemaVersion identifies the admitted burnchain-topology digest contract.
	SchemaVersion  = "stacks-network-admitted-burnchain-topology/v1"
	defaultRPCPort = int32(18443)
	defaultP2PPort = int32(18444)
)

// Payload is the canonical graph-identity input. Observation time, network
// generation, and Kubernetes resource versions remain alongside the digest so
// restoring identical graph content restores the same digest.
type Payload struct {
	Bindings      []attacknetv1beta1.BurnchainActorBinding `json:"bindings,omitempty"`
	Nodes         []attacknetv1beta1.AdmittedBitcoinNode   `json:"nodes"`
	SchemaVersion string                                   `json:"schemaVersion"`
}

// Validate checks references and port and policy invariants without requiring
// admitted workload status.
func Validate(network *attacknetv1beta1.StacksNetwork) error {
	if network == nil {
		return errors.New("StacksNetwork is required")
	}
	if len(network.Spec.Burnchain.Nodes) == 0 || len(network.Spec.Burnchain.Nodes) > 32 {
		return errors.New("burnchain topology requires 1..32 Bitcoin nodes")
	}
	if network.Spec.Burnchain.PolicyRef.Name == "" {
		return errors.New("spec.burnchain.policyRef.name is required")
	}
	nodes := make(map[string]attacknetv1beta1.BitcoinNodeSpec, len(network.Spec.Burnchain.Nodes))
	policies := make(map[string]string, len(network.Spec.Burnchain.Nodes))
	for _, node := range network.Spec.Burnchain.Nodes {
		if node.Name == "" {
			return errors.New("Bitcoin node name is required")
		}
		if _, duplicate := nodes[node.Name]; duplicate {
			return fmt.Errorf("duplicate Bitcoin node %q", node.Name)
		}
		if err := validatePort(node.Name, "rpcPort", EffectiveRPCPort(node)); err != nil {
			return err
		}
		if err := validatePort(node.Name, "p2pPort", EffectiveP2PPort(node)); err != nil {
			return err
		}
		if EffectiveRPCPort(node) == EffectiveP2PPort(node) {
			return fmt.Errorf("Bitcoin node %q RPC and P2P ports must differ", node.Name)
		}
		nodes[node.Name] = node
		policy := policyName(network.Spec.Burnchain.PolicyRef.Name, node)
		if policy == "" {
			return fmt.Errorf("Bitcoin node %q has no cadence policy", node.Name)
		}
		if previous, duplicate := policies[policy]; duplicate {
			return fmt.Errorf("BurnchainPolicy %q is shared by Bitcoin nodes %q and %q", policy, previous, node.Name)
		}
		policies[policy] = node.Name
	}
	for _, node := range network.Spec.Burnchain.Nodes {
		seen := make(map[string]struct{}, len(node.PeerRefs))
		for _, peer := range node.PeerRefs {
			if peer == node.Name {
				return fmt.Errorf("Bitcoin node %q cannot peer with itself", node.Name)
			}
			if _, exists := nodes[peer]; !exists {
				return fmt.Errorf("Bitcoin node %q references unknown peer %q", node.Name, peer)
			}
			if _, duplicate := seen[peer]; duplicate {
				return fmt.Errorf("Bitcoin node %q duplicates peer %q", node.Name, peer)
			}
			seen[peer] = struct{}{}
		}
	}
	for _, node := range network.Spec.Nodes {
		if _, exists := nodes[node.BurnchainNodeRef]; !exists {
			return fmt.Errorf("Stacks node %q references unknown burnchain node %q", node.Name, node.BurnchainNodeRef)
		}
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			if _, exists := nodes[member.BurnchainNodeRef]; !exists {
				return fmt.Errorf("signer node %q references unknown burnchain node %q", member.NodeName, member.BurnchainNodeRef)
			}
		}
	}
	return nil
}

// PolicyName returns the cadence policy bound to one Bitcoin node.
func PolicyName(network *attacknetv1beta1.StacksNetwork, nodeName string) (string, error) {
	if network == nil {
		return "", errors.New("StacksNetwork is required")
	}
	for _, node := range network.Spec.Burnchain.Nodes {
		if node.Name == nodeName {
			name := policyName(network.Spec.Burnchain.PolicyRef.Name, node)
			if name == "" {
				return "", fmt.Errorf("Bitcoin node %q has no cadence policy", nodeName)
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("Bitcoin node %q is absent from the topology", nodeName)
}

// PolicyBindings returns the normalized policy-to-node mapping.
func PolicyBindings(network *attacknetv1beta1.StacksNetwork) (map[string]string, error) {
	if err := Validate(network); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(network.Spec.Burnchain.Nodes))
	for _, node := range network.Spec.Burnchain.Nodes {
		result[policyName(network.Spec.Burnchain.PolicyRef.Name, node)] = node.Name
	}
	return result, nil
}

// Build creates the normalized admitted graph after every Bitcoin workload and
// cadence-policy identity is available. Unrelated Stacks actor readiness does
// not change this structural graph identity.
func Build(network *attacknetv1beta1.StacksNetwork, policyUIDs map[string]string) (*attacknetv1beta1.AdmittedBurnchainTopology, error) {
	if err := Validate(network); err != nil {
		return nil, err
	}
	statuses := make(map[string]attacknetv1beta1.ActorStatus, len(network.Status.Actors))
	for _, status := range network.Status.Actors {
		statuses[status.Name] = status
	}
	nodes := make([]attacknetv1beta1.AdmittedBitcoinNode, 0, len(network.Spec.Burnchain.Nodes))
	for _, node := range network.Spec.Burnchain.Nodes {
		status, exists := statuses[node.Name]
		if !exists || status.Role != "burnchain" || !status.IdentityReady || status.ServiceName == "" {
			return nil, fmt.Errorf("Bitcoin node %q lacks an admitted workload identity", node.Name)
		}
		peers := append([]string(nil), node.PeerRefs...)
		slices.Sort(peers)
		policy := policyName(network.Spec.Burnchain.PolicyRef.Name, node)
		policyUID := policyUIDs[policy]
		if policyUID == "" {
			return nil, fmt.Errorf("BurnchainPolicy %q lacks an admitted UID", policy)
		}
		nodes = append(nodes, attacknetv1beta1.AdmittedBitcoinNode{
			Name: node.Name, ServiceName: status.ServiceName,
			RPCPort: EffectiveRPCPort(node), P2PPort: EffectiveP2PPort(node),
			PeerRefs: peers, PolicyRef: policy, PolicyUID: policyUID,
			PolicyServiceName: PolicyServiceName(policy),
		})
	}
	slices.SortFunc(nodes, func(left, right attacknetv1beta1.AdmittedBitcoinNode) int {
		return strings.Compare(left.Name, right.Name)
	})
	bindings := actorBindings(network)
	payload := Payload{
		Bindings: bindings, Nodes: nodes, SchemaVersion: SchemaVersion,
	}
	digest, err := canonical.Digest(payload)
	if err != nil {
		return nil, fmt.Errorf("digest admitted burnchain topology: %w", err)
	}
	return &attacknetv1beta1.AdmittedBurnchainTopology{
		SchemaVersion: SchemaVersion, Digest: digest,
		ObservedGeneration: network.Generation, ObservedAt: network.Status.InventoryObservedAt,
		Nodes: nodes, Bindings: bindings,
	}, nil
}

// PolicyServiceName returns the stable Service name for one policy clock.
func PolicyServiceName(policyName string) string {
	candidate := policyName + "-clock"
	if len(candidate) <= 63 {
		return candidate
	}
	digest := sha256.Sum256([]byte(candidate))
	return strings.TrimRight(candidate[:54], "-") + "-" + hex.EncodeToString(digest[:4])
}

// Published verifies that status contains the graph derived from the current
// admitted workload state.
func Published(network *attacknetv1beta1.StacksNetwork) (*attacknetv1beta1.AdmittedBurnchainTopology, error) {
	if network == nil || network.Status.BurnchainTopology == nil || network.Status.BurnchainTopology.Digest == "" {
		return nil, errors.New("StacksNetwork has no published admitted burnchain topology")
	}
	policyUIDs := make(map[string]string, len(network.Status.BurnchainTopology.Nodes))
	for _, node := range network.Status.BurnchainTopology.Nodes {
		if node.PolicyRef == "" || node.PolicyUID == "" {
			return nil, errors.New("published burnchain topology has an incomplete policy identity")
		}
		if previous, duplicate := policyUIDs[node.PolicyRef]; duplicate && previous != node.PolicyUID {
			return nil, fmt.Errorf("published BurnchainPolicy %q has conflicting UIDs", node.PolicyRef)
		}
		policyUIDs[node.PolicyRef] = node.PolicyUID
	}
	calculated, err := Build(network, policyUIDs)
	if err != nil {
		return nil, err
	}
	published := network.Status.BurnchainTopology
	publishedDigest, err := canonical.Digest(Payload{
		Bindings: published.Bindings, Nodes: published.Nodes, SchemaVersion: published.SchemaVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("digest published burnchain topology: %w", err)
	}
	if published.Digest != publishedDigest || !reflect.DeepEqual(published, calculated) {
		return nil, fmt.Errorf("admitted burnchain topology mismatch: published %s, calculated %s", published.Digest, calculated.Digest)
	}
	return calculated, nil
}

// VerifyPolicyIdentity proves that one directly-read cadence policy is the
// object admitted for a Bitcoin actor. Callers must supply a topology obtained
// from a direct StacksNetwork read or an identity-bracketed snapshot.
func VerifyPolicyIdentity(
	topology *attacknetv1beta1.AdmittedBurnchainTopology,
	networkName, actor string,
	policy *attacknetv1beta1.BurnchainPolicy,
) error {
	if topology == nil || topology.Digest == "" {
		return errors.New("admitted burnchain topology is unavailable")
	}
	var admitted *attacknetv1beta1.AdmittedBitcoinNode
	for index := range topology.Nodes {
		if topology.Nodes[index].Name == actor {
			admitted = &topology.Nodes[index]
			break
		}
	}
	if admitted == nil {
		return fmt.Errorf("Bitcoin actor %q is absent from the admitted burnchain topology", actor)
	}
	if policy == nil || policy.Name != admitted.PolicyRef || string(policy.UID) != admitted.PolicyUID ||
		policy.Spec.NetworkRef != networkName || policy.Spec.BitcoinNodeRef != actor {
		return fmt.Errorf("BurnchainPolicy for Bitcoin actor %q differs from admitted identity", actor)
	}
	return nil
}

func actorBindings(network *attacknetv1beta1.StacksNetwork) []attacknetv1beta1.BurnchainActorBinding {
	bindings := make([]attacknetv1beta1.BurnchainActorBinding, 0, len(network.Spec.Nodes)+len(network.Spec.SignerSets))
	for _, node := range network.Spec.Nodes {
		bindings = append(bindings, attacknetv1beta1.BurnchainActorBinding{Actor: node.Name, BitcoinNodeRef: node.BurnchainNodeRef})
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			bindings = append(bindings, attacknetv1beta1.BurnchainActorBinding{Actor: member.NodeName, BitcoinNodeRef: member.BurnchainNodeRef})
		}
	}
	slices.SortFunc(bindings, func(left, right attacknetv1beta1.BurnchainActorBinding) int {
		return strings.Compare(left.Actor, right.Actor)
	})
	return bindings
}

func policyName(fallback string, node attacknetv1beta1.BitcoinNodeSpec) string {
	if node.PolicyRef != nil && node.PolicyRef.Name != "" {
		return node.PolicyRef.Name
	}
	return fallback
}

// EffectiveRPCPort returns the declared Bitcoin RPC port or its regtest default.
func EffectiveRPCPort(node attacknetv1beta1.BitcoinNodeSpec) int32 {
	return effectivePort(node.RPCPort, defaultRPCPort)
}

// EffectiveP2PPort returns the declared Bitcoin P2P port or its regtest default.
func EffectiveP2PPort(node attacknetv1beta1.BitcoinNodeSpec) int32 {
	return effectivePort(node.P2PPort, defaultP2PPort)
}

func effectivePort(value, fallback int32) int32 {
	if value == 0 {
		return fallback
	}
	return value
}

func validatePort(node, field string, value int32) error {
	if value < 1 || value > 65535 {
		return fmt.Errorf("Bitcoin node %q %s must be within 1..65535", node, field)
	}
	return nil
}
