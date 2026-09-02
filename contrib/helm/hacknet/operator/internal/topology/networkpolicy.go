package topology

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const (
	egressProfileLabel           = "testing.stacks.org/egress-profile"
	egressPolicyDigestAnnotation = "testing.stacks.org/egress-policy-digest"
)

// egressPolicy renders the default-deny egress boundary for one explicitly
// restricted actor. An absent profile preserves normal network behavior.
func (c actorContext) egressPolicy() (*networkingv1.NetworkPolicy, error) {
	profile := c.actor.Labels[egressProfileLabel]
	switch profile {
	case "":
		return nil, nil
	case "unrestricted":
		return nil, nil
	case "restricted":
	default:
		return nil, fmt.Errorf("actor %q has unsupported egress profile %q", c.actor.Name, profile)
	}
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	allowedActors := make([]string, 0, len(c.actor.Dependencies)+len(c.actor.EgressPeers))
	seenActors := make(map[string]struct{}, cap(allowedActors))
	for _, dependency := range c.actor.Dependencies {
		if dependency.Actor == "" {
			continue
		}
		if _, seen := seenActors[dependency.Actor]; seen {
			continue
		}
		seenActors[dependency.Actor] = struct{}{}
		allowedActors = append(allowedActors, dependency.Actor)
	}
	for _, actor := range c.actor.EgressPeers {
		if actor == "" {
			return nil, fmt.Errorf("actor %q has an empty egress peer", c.actor.Name)
		}
		if _, seen := seenActors[actor]; seen {
			continue
		}
		seenActors[actor] = struct{}{}
		allowedActors = append(allowedActors, actor)
	}
	egress := make([]networkingv1.NetworkPolicyEgressRule, 0, len(allowedActors)+1)
	for _, actor := range allowedActors {
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{networkLabel: c.network.Name, actorLabel: actor}},
		}}})
	}
	egress = append(egress,
		networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: intstrPointer(53)}, {Protocol: &tcp, Port: intstrPointer(53)}},
		},
	)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: c.metadata(),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{networkLabel: c.network.Name, actorLabel: c.actor.Name}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}
	if err := c.own(policy); err != nil {
		return nil, err
	}
	digest, err := egressPolicyDigest(policy)
	if err != nil {
		return nil, err
	}
	policy.Annotations = map[string]string{egressPolicyDigestAnnotation: digest}
	return policy, nil
}

// egressPolicyDigest binds the API-default-independent policy spec admitted
// for one restricted actor.
func egressPolicyDigest(policy *networkingv1.NetworkPolicy) (string, error) {
	if policy == nil {
		return "", fmt.Errorf("egress NetworkPolicy is required")
	}
	digest, err := canonical.Digest(policy.Spec)
	if err != nil {
		return "", fmt.Errorf("digest egress NetworkPolicy %s: %w", policy.Name, err)
	}
	return digest, nil
}

func intstrPointer(value int) *intstr.IntOrString {
	port := intstr.FromInt(value)
	return &port
}
