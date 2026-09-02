package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
)

// CompileV1Beta1 converts the domain topology to the proven A4 workload model.
// The compatibility model remains internal and can be removed after the
// v1beta1 renderer has independent resource-tree coverage.
func CompileV1Beta1(network *attacknetv1beta1.StacksNetwork) (*attacknetv1alpha1.StacksNetwork, error) {
	if err := validateV1Beta1Network(network); err != nil {
		return nil, err
	}
	compiled := &attacknetv1alpha1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1alpha1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: *network.ObjectMeta.DeepCopy(),
		Spec: attacknetv1alpha1.StacksNetworkSpec{
			Suspended: network.Spec.Suspended,
			Defaults:  compileDefaults(network.Spec.Defaults),
			Telemetry: compileTelemetry(network.Spec.Telemetry),
			Probe:     compileProbe(network.Spec.Probe),
		},
	}
	bitcoinServices := make(map[string]string, len(network.Spec.Burnchain.Nodes))
	bitcoinNodes := make(map[string]attacknetv1beta1.BitcoinNodeSpec, len(network.Spec.Burnchain.Nodes))
	for _, node := range network.Spec.Burnchain.Nodes {
		bitcoinNodes[node.Name] = node
	}
	for i := range network.Spec.Burnchain.Nodes {
		actor, err := compileBitcoinActor(network, &network.Spec.Burnchain.Nodes[i], bitcoinNodes)
		if err != nil {
			return nil, err
		}
		policyName, err := burnchaintopology.PolicyName(network, actor.Name)
		if err != nil {
			return nil, err
		}
		bitcoinServices[actor.Name] = burnchaintopology.PolicyServiceName(policyName)
		compiled.Spec.Actors = append(compiled.Spec.Actors, actor)
	}
	for i := range network.Spec.Nodes {
		actor, err := compileStacksNodeActor(network, &network.Spec.Nodes[i], bitcoinServices, "", 0)
		if err != nil {
			return nil, err
		}
		compiled.Spec.Actors = append(compiled.Spec.Actors, actor)
	}
	for setIndex := range network.Spec.SignerSets {
		set := &network.Spec.SignerSets[setIndex]
		for memberIndex := range set.Members {
			member := &set.Members[memberIndex]
			node, signer, observer, err := compileSignerMember(network, member, bitcoinServices)
			if err != nil {
				return nil, err
			}
			compiled.Spec.Actors = append(compiled.Spec.Actors, node, signer)
			if observer != nil {
				compiled.Spec.Actors = append(compiled.Spec.Actors, *observer)
			}
		}
	}
	if network.Spec.Enrollment != nil {
		compiled.Spec.Actors = append(compiled.Spec.Actors, compileSignerEnrollment(network.Spec.Enrollment))
	}
	for i := range network.Spec.RawActors {
		actor, err := compileRawActor(network, &network.Spec.RawActors[i])
		if err != nil {
			return nil, err
		}
		compiled.Spec.Actors = append(compiled.Spec.Actors, actor)
	}
	return compiled, nil
}

// ValidateV1Beta1 validates both the typed topology and the compiled workload
// model without requiring API-server-assigned metadata. It uses a placeholder
// for the chart-owned probe image so offline CLI validation applies the same
// port and workload invariants as reconciliation.
func ValidateV1Beta1(network *attacknetv1beta1.StacksNetwork) error {
	if network == nil {
		return fmt.Errorf("network is required")
	}
	candidate := network.DeepCopy()
	if candidate.UID == "" {
		candidate.UID = types.UID("offline-validation")
	}
	compiled, err := CompileV1Beta1(candidate)
	if err != nil {
		return err
	}
	applyV1Beta1RendererDefaults(compiled, "attacknet.invalid/trusted-probe:validation", corev1.PullIfNotPresent)
	return validateNetwork(compiled)
}

func compileSignerEnrollment(enrollment *attacknetv1beta1.SignerEnrollmentSpec) attacknetv1alpha1.ActorSpec {
	stackingCycles := enrollment.StackingCycles
	if stackingCycles == 0 {
		stackingCycles = 12
	}
	pox5Cycles := enrollment.PoX5StackingCycles
	if pox5Cycles == 0 {
		pox5Cycles = 96
	}
	renewalWindow := enrollment.PoX5RenewalWindowCycles
	if renewalWindow == 0 {
		renewalWindow = 48
	}
	interval := enrollment.IntervalSeconds
	if interval == 0 {
		interval = 2
	}
	secret := enrollment.CredentialsSecretRef
	actor := attacknetv1alpha1.ActorSpec{
		Name: enrollment.Name, Role: "infrastructure", Image: enrollment.Image,
		Command:      []string{"npx", "tsx", "/stacker/stacking.ts"},
		Dependencies: []attacknetv1alpha1.ActorDependency{{Actor: enrollment.NodeRef, Port: 20443}},
		Env: []corev1.EnvVar{
			{Name: "STACKS_CORE_RPC_HOST", Value: "${SERVICE:" + enrollment.NodeRef + "}"},
			{Name: "STACKS_CORE_RPC_PORT", Value: "20443"},
			{Name: "STACKING_KEYS", ValueFrom: secretEnv(secret.Name, secret.KeysKey)},
			{Name: "STACKING_ADDRESSES", ValueFrom: secretEnv(secret.Name, secret.AddressesKey)},
			{Name: "STACKING_CYCLES", Value: strconv.Itoa(int(stackingCycles))},
			{Name: "POX5_STACKING_CYCLES", Value: strconv.Itoa(int(pox5Cycles))},
			{Name: "POX5_RENEWAL_WINDOW_CYCLES", Value: strconv.Itoa(int(renewalWindow))},
			{Name: "STACKING_INTERVAL", Value: strconv.Itoa(int(interval))},
			{Name: "EPOCH_4_FIXTURE_DEPLOY_HEIGHT", Value: "223"},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"test", "-s", "/tmp/attacknet-stacker-status.json"}}},
			PeriodSeconds: 2, FailureThreshold: 60,
		},
	}
	applyWorkload(&actor, enrollment.Workload)
	applyAdvanced(&actor, enrollment.Advanced)
	return actor
}

func secretEnv(name, key string) *corev1.EnvVarSource {
	return &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: key,
	}}
}

func compileDefaults(value attacknetv1beta1.NetworkDefaults) attacknetv1alpha1.StacksNetworkDefaults {
	return attacknetv1alpha1.StacksNetworkDefaults{
		NodeImage:                     value.NodeImage,
		SignerImage:                   value.SignerImage,
		BurnchainImage:                value.BitcoinImage,
		DependencyImage:               value.DependencyImage,
		ImagePullPolicy:               value.ImagePullPolicy,
		ImagePullSecrets:              append([]corev1.LocalObjectReference(nil), value.ImagePullSecrets...),
		Storage:                       compileStorage(value.Workload.Storage),
		Resources:                     copyResourceRequirements(value.Workload.Resources),
		TerminationGracePeriodSeconds: copyInt64(value.Workload.TerminationGracePeriodSeconds),
		NodeSelector:                  copyStringMap(value.Workload.NodeSelector),
		Affinity:                      copyAffinity(value.Workload.Affinity),
		Tolerations:                   append([]corev1.Toleration(nil), value.Workload.Tolerations...),
		TopologySpreadConstraints:     append([]corev1.TopologySpreadConstraint(nil), value.Workload.TopologySpreadConstraints...),
	}
}

func compileBitcoinActor(network *attacknetv1beta1.StacksNetwork, node *attacknetv1beta1.BitcoinNodeSpec, nodes map[string]attacknetv1beta1.BitcoinNodeSpec) (attacknetv1alpha1.ActorSpec, error) {
	rpcPort := burnchaintopology.EffectiveRPCPort(*node)
	p2pPort := burnchaintopology.EffectiveP2PPort(*node)
	config, err := compileConfig(network, profileContext{
		actor: node.Name, role: "burnchain",
		burnchainRPCPort: rpcPort, burnchainP2PPort: p2pPort,
	}, node.Config)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, err
	}
	args := []string{
		"-conf=" + strings.TrimRight(config.MountPath, "/") + "/" + config.Key,
		"-datadir=/data", "-nosettings", fmt.Sprintf("-rpcport=%d", rpcPort), fmt.Sprintf("-port=%d", p2pPort),
	}
	peers := append([]string(nil), node.PeerRefs...)
	sort.Strings(peers)
	for _, peer := range peers {
		peerNode := nodes[peer]
		peerPort := burnchaintopology.EffectiveP2PPort(peerNode)
		args = append(args, fmt.Sprintf("-addnode=${SERVICE:%s}:%d", peer, peerPort))
	}
	actor := attacknetv1alpha1.ActorSpec{
		Name: node.Name, Role: "burnchain", Suspended: node.Suspended,
		Image: node.Image, Config: config,
		Command: []string{"bitcoind"},
		Args:    args,
		Ports: []attacknetv1alpha1.ActorPort{
			{Name: "rpc", ContainerPort: rpcPort, ServicePort: rpcPort, Protocol: corev1.ProtocolTCP},
			{Name: "p2p", ContainerPort: p2pPort, ServicePort: p2pPort, Protocol: corev1.ProtocolTCP},
		},
	}
	applyWorkload(&actor, node.Workload)
	applyAdvanced(&actor, node.Advanced)
	return actor, nil
}

func compileStacksNodeActor(network *attacknetv1beta1.StacksNetwork, node *attacknetv1beta1.StacksNodeSpec, bitcoinNodes map[string]string, signerName string, signerIndex int32) (attacknetv1alpha1.ActorSpec, error) {
	policyService, ok := bitcoinNodes[node.BurnchainNodeRef]
	if !ok {
		return attacknetv1alpha1.ActorSpec{}, fmt.Errorf("node %q references unknown burnchain node %q", node.Name, node.BurnchainNodeRef)
	}
	bitcoinNode := bitcoinNodeByName(network, node.BurnchainNodeRef)
	config, err := compileConfig(network, profileContext{
		actor:            node.Name,
		role:             string(node.Role),
		burnchainNode:    node.BurnchainNodeRef,
		signerName:       signerName,
		signerIndex:      signerIndex,
		eventDispatcher:  "queued",
		burnchainRPCPort: burnchaintopology.EffectiveRPCPort(bitcoinNode),
		burnchainP2PPort: burnchaintopology.EffectiveP2PPort(bitcoinNode),
	}, node.Config)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, err
	}
	role := string(node.Role)
	if signerName != "" {
		role = "companion"
	}
	actor := attacknetv1alpha1.ActorSpec{
		Name: node.Name, Role: role, Suspended: node.Suspended,
		Image: node.Image, Config: config,
		Ports: []attacknetv1alpha1.ActorPort{
			{Name: "rpc", ContainerPort: 20443, ServicePort: 20443, Protocol: corev1.ProtocolTCP},
			{Name: "p2p", ContainerPort: 20444, ServicePort: 20444, Protocol: corev1.ProtocolTCP},
			{Name: "metrics", ContainerPort: 20446, ServicePort: 20446, Protocol: corev1.ProtocolTCP},
		},
		Dependencies: []attacknetv1alpha1.ActorDependency{
			{Actor: node.BurnchainNodeRef, Port: burnchaintopology.EffectiveRPCPort(bitcoinNode)},
			{Service: policyService, Port: 18500},
		},
		RuntimeExposure: "reachable",
		Env: []corev1.EnvVar{
			{Name: "STACKS_ATTACKNET_CONFIG_TEMPLATE", Value: actorConfigPath(config)},
			{Name: "STACKS_ATTACKNET_SERVICE_MAP", Value: serviceMapTemplate(network)},
		},
	}
	// The Pod address does not exist when any node configuration is authored.
	// Render inside the workload so Secret-backed configs stay opaque to the
	// operator while receiving the same deterministic substitution as generated
	// and ConfigMap-backed templates.
	actor.Command = []string{"/bin/bash", "-ceu", configureActorScript, "--", "stacks-node", "start", "--config", "/tmp/stacks-attacknet-config.toml"}
	if signerName != "" {
		actor.Dependencies = append(actor.Dependencies, attacknetv1alpha1.ActorDependency{Actor: signerName, Port: 30000})
	}
	applyWorkload(&actor, node.Workload)
	applyAdvanced(&actor, node.Advanced)
	return actor, nil
}

func compileSignerMember(network *attacknetv1beta1.StacksNetwork, member *attacknetv1beta1.SignerMemberSpec, bitcoinNodes map[string]string) (attacknetv1alpha1.ActorSpec, attacknetv1alpha1.ActorSpec, *attacknetv1alpha1.ActorSpec, error) {
	nodeSpec := attacknetv1beta1.StacksNodeSpec{Name: member.NodeName, Role: attacknetv1beta1.StacksNodeFollower, Image: member.NodeImage, BurnchainNodeRef: member.BurnchainNodeRef, Config: member.NodeConfig, Workload: member.NodeWorkload, Advanced: member.NodeAdvanced, Suspended: member.Suspended}
	node, err := compileStacksNodeActor(network, &nodeSpec, bitcoinNodes, member.Name, member.Index)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, err
	}
	index := member.Index
	weight := float64(member.Weight)
	// The signer and its co-located Stacks node are one signer-impact unit.
	// Preserve the complete identity on both compiled actors so canonical
	// reward-set resolution can deduplicate them by signing key and account for
	// either actor being targeted by a fault campaign.
	node.SignerIndex = &index
	node.SignerWeight = &weight
	node.SignerPublicKey = member.PublicKey
	signerConfig, err := compileConfig(network, profileContext{
		actor:       member.Name,
		role:        "signer",
		signerName:  member.Name,
		signerNode:  member.NodeName,
		signerIndex: member.Index,
	}, member.SignerConfig)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, err
	}
	signer := attacknetv1alpha1.ActorSpec{
		Name: member.Name, Role: "signer", SignerIndex: &index,
		SignerWeight: &weight, SignerPublicKey: member.PublicKey,
		Suspended: member.Suspended, Image: member.SignerImage, Config: signerConfig,
		RuntimeExposure: "reachable",
		Ports: []attacknetv1alpha1.ActorPort{
			{Name: "events", ContainerPort: 30000, ServicePort: 30000, Protocol: corev1.ProtocolTCP},
			{Name: "metrics", ContainerPort: 31000, ServicePort: 31000, Protocol: corev1.ProtocolTCP},
		},
		// The node waits for the signer event endpoint, so making the reverse
		// relationship a startup dependency would deadlock. It remains an
		// explicit, actor-scoped egress relationship for restricted policies.
		EgressPeers: []string{member.NodeName},
		Env: []corev1.EnvVar{
			{Name: "STACKS_ATTACKNET_CONFIG_TEMPLATE", Value: actorConfigPath(signerConfig)},
			{Name: "STACKS_ATTACKNET_SERVICE_MAP", Value: serviceMapTemplate(network)},
		},
	}
	// Complete signer configs remain Secret-backed, so resolve logical actor
	// references inside the Pod without granting the operator Secret access.
	signer.Command = []string{"/bin/bash", "-ceu", configureActorScript, "--", "stacks-signer", "run", "--config", "/tmp/stacks-attacknet-config.toml"}
	applyWorkload(&signer, member.SignerWorkload)
	applyAdvanced(&signer, member.SignerAdvanced)
	if member.Adversarial == nil {
		return node, signer, nil, nil
	}
	policy, err := adversarial.Normalize(member.Adversarial)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, fmt.Errorf("signer %q adversarial policy: %w", member.Name, err)
	}
	encoded, err := adversarial.Encode(policy)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, err
	}
	digest, err := adversarial.Digest(policy)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, err
	}
	signer.Env = append(signer.Env,
		corev1.EnvVar{Name: "STACKS_SIGNER_ATTACKNET_POLICY", Value: encoded},
		corev1.EnvVar{Name: "STACKS_SIGNER_ATTACKNET_POLICY_DIGEST", Value: digest},
	)
	if signer.Labels == nil {
		signer.Labels = map[string]string{}
	}
	signer.Labels["testing.stacks.org/adversarial"] = "true"
	signer.Labels["testing.stacks.org/egress-profile"] = member.Adversarial.Egress.Profile
	signer.AdversarialPolicyDigest = digest
	signer.AdversarialEgressProfile = member.Adversarial.Egress.Profile
	observer, err := compileAdversarialObserver(network, member, digest)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, attacknetv1alpha1.ActorSpec{}, nil, err
	}
	return node, signer, &observer, nil
}

func compileAdversarialObserver(network *attacknetv1beta1.StacksNetwork, member *attacknetv1beta1.SignerMemberSpec, policyDigest string) (attacknetv1alpha1.ActorSpec, error) {
	name := adversarial.ObserverName(member.Name)
	peers := map[string]any{
		member.Name:     map[string]any{"host": "${SERVICE:" + member.Name + "}", "ports": map[string]int32{"events": 30000, "metrics": 31000}},
		member.NodeName: map[string]any{"host": "${SERVICE:" + member.NodeName + "}", "ports": map[string]int32{"p2p": 20444, "rpc": 20443, "metrics": 20446}},
	}
	encodedPeers, err := json.Marshal(peers)
	if err != nil {
		return attacknetv1alpha1.ActorSpec{}, fmt.Errorf("encode adversarial observer peers: %w", err)
	}
	disabled := false
	runAs := int64(65532)
	return attacknetv1alpha1.ActorSpec{
		Name: name, Role: "observer", Image: member.Adversarial.Observer.Image,
		ImagePullPolicy: member.Adversarial.Observer.ImagePullPolicy,
		RuntimeExposure: "ready", AdversarialPolicyDigest: policyDigest,
		AdversarialEgressProfile: "restricted",
		Ports:                    []attacknetv1alpha1.ActorPort{{Name: "probe", ContainerPort: 18080, ServicePort: 18080, Protocol: corev1.ProtocolTCP}},
		Dependencies:             []attacknetv1alpha1.ActorDependency{{Actor: member.Name, Port: 30000}, {Actor: member.NodeName, Port: 20443}},
		Env: []corev1.EnvVar{
			{Name: "PROBE_ACTOR", Value: name},
			{Name: "PROBE_PORT", Value: "18080"},
			{Name: "PROBE_DATA_ROOT", Value: "/data"},
			{Name: "PROBE_DNS_CONTROL", Value: "kubernetes.default.svc.cluster.local"},
			{Name: "PROBE_PEERS_JSON", Value: string(encodedPeers)},
			{Name: "PROBE_ADVERSARIAL_TARGET", Value: member.Name},
			{Name: "PROBE_ADVERSARIAL_POLICY_DIGEST", Value: policyDigest},
		},
		Storage: &attacknetv1alpha1.StorageSpec{Enabled: &disabled, MountPath: "/data"},
		// The observer image is itself the bounded probe server. Disable the
		// ordinary actor probe sidecar so one Pod never contains a second
		// observation identity or collides on the reserved probe port.
		Probe:     &attacknetv1alpha1.ProbeSpec{Enabled: &disabled},
		Resources: copyResourceRequirements(member.Adversarial.Observer.Resources),
		ContainerSecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPointer(false), ReadOnlyRootFilesystem: boolPointer(true),
			RunAsNonRoot: boolPointer(true), RunAsUser: &runAs, RunAsGroup: &runAs,
			Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Labels: map[string]string{
			"testing.stacks.org/adversarial-observer": "true",
			"testing.stacks.org/egress-profile":       "restricted",
			"testing.stacks.org/observes-actor":       member.Name,
		},
	}, nil
}

func boolPointer(value bool) *bool { return &value }

func compileRawActor(network *attacknetv1beta1.StacksNetwork, raw *attacknetv1beta1.RawActorSpec) (attacknetv1alpha1.ActorSpec, error) {
	var config *attacknetv1alpha1.ActorConfig
	var err error
	if raw.Config != nil {
		config, err = compileConfig(network, profileContext{actor: raw.Name, role: raw.Role}, *raw.Config)
		if err != nil {
			return attacknetv1alpha1.ActorSpec{}, err
		}
	}
	ports := make([]attacknetv1alpha1.ActorPort, 0, len(raw.Ports))
	for _, port := range raw.Ports {
		ports = append(ports, attacknetv1alpha1.ActorPort(port))
	}
	dependencies := make([]attacknetv1alpha1.ActorDependency, 0, len(raw.Dependencies))
	for _, dependency := range raw.Dependencies {
		dependencies = append(dependencies, attacknetv1alpha1.ActorDependency{Actor: dependency.Actor, Port: dependency.Port})
	}
	actor := attacknetv1alpha1.ActorSpec{Name: raw.Name, Role: raw.Role, Image: raw.Image, Suspended: raw.Suspended, Config: config, Ports: ports, Dependencies: dependencies}
	applyWorkload(&actor, raw.Workload)
	applyAdvanced(&actor, raw.Advanced)
	return actor, nil
}

type profileContext struct {
	actor            string
	role             string
	burnchainNode    string
	signerName       string
	signerNode       string
	signerIndex      int32
	eventDispatcher  string
	burnchainRPCPort int32
	burnchainP2PPort int32
}

func actorConfigPath(config *attacknetv1alpha1.ActorConfig) string {
	return strings.TrimRight(config.MountPath, "/") + "/" + config.Key
}

func compileConfig(network *attacknetv1beta1.StacksNetwork, context profileContext, source attacknetv1beta1.ConfigSource) (*attacknetv1alpha1.ActorConfig, error) {
	sources := 0
	if source.Generated != nil {
		sources++
	}
	if source.ConfigMapRef != nil {
		sources++
	}
	if source.SecretRef != nil {
		sources++
	}
	if sources != 1 {
		return nil, fmt.Errorf("actor %q config requires exactly one generated, ConfigMap, or Secret source", context.actor)
	}
	mountPath := func(value string) string {
		if value == "" {
			return "/etc/stacks"
		}
		return value
	}
	defaultKey := func(value string) string {
		if value != "" {
			return value
		}
		switch context.role {
		case "burnchain":
			return "bitcoin.conf"
		case "signer":
			return "signer.toml"
		default:
			return "config.toml"
		}
	}
	if source.ConfigMapRef != nil {
		return &attacknetv1alpha1.ActorConfig{Key: defaultKey(source.ConfigMapRef.Key), MountPath: mountPath(source.ConfigMapRef.MountPath), ConfigMapRef: &corev1.LocalObjectReference{Name: source.ConfigMapRef.Name}, ExpectedDigest: source.ExpectedDigest}, nil
	}
	if source.SecretRef != nil {
		return &attacknetv1alpha1.ActorConfig{Key: defaultKey(source.SecretRef.Key), MountPath: mountPath(source.SecretRef.MountPath), SecretRef: &corev1.LocalObjectReference{Name: source.SecretRef.Name}, ExpectedDigest: source.ExpectedDigest}, nil
	}
	if source.ExpectedDigest != "" {
		return nil, fmt.Errorf("actor %q generated config cannot declare an external expected digest", context.actor)
	}
	files, key, err := renderGeneratedProfile(network, context, *source.Generated)
	if err != nil {
		return nil, err
	}
	return &attacknetv1alpha1.ActorConfig{Files: files, Key: key, MountPath: "/etc/stacks"}, nil
}

func renderGeneratedProfile(network *attacknetv1beta1.StacksNetwork, context profileContext, generated attacknetv1beta1.GeneratedConfigSpec) (map[string]string, string, error) {
	if context.role == "signer" {
		return nil, "", fmt.Errorf("actor %q signer requires a complete Secret-backed config so its private key is not stored in StacksNetwork", context.actor)
	}
	switch generated.Profile {
	case "bitcoin-regtest/v1":
		if generated.Seed != "" || len(generated.BootstrapPeers) > 0 || generated.EventDispatcher != "" {
			return nil, "", fmt.Errorf("actor %q bitcoin profile does not accept node-profile overlays", context.actor)
		}
		return map[string]string{"bitcoin.conf": bitcoinRegtestConfig(context.burnchainRPCPort)}, "bitcoin.conf", nil
	case "nakamoto-regtest-node/v1":
		if context.burnchainNode == "" {
			return nil, "", fmt.Errorf("actor %q node profile requires a burnchain node", context.actor)
		}
		if context.role == "miner" {
			return nil, "", fmt.Errorf("actor %q miner requires a complete Secret-backed config so mining credentials are not stored in StacksNetwork", context.actor)
		}
		return map[string]string{"config.toml": nakamotoNodeConfig(network, context, generated)}, "config.toml", nil
	default:
		return nil, "", fmt.Errorf("actor %q uses unknown generated config profile %q", context.actor, generated.Profile)
	}
}

func bitcoinRegtestConfig(rpcPort int32) string {
	return fmt.Sprintf("regtest=1\nprinttoconsole=1\nserver=1\ntxindex=1\ndiscover=0\ndns=1\ndnsseed=0\nlistenonion=0\nfallbackfee=0.00001\n\n[regtest]\nrpcbind=0.0.0.0:%d\nrpcallowip=0.0.0.0/0\nrpcuser=devnet\nrpcpassword=devnet\n", rpcPort)
}

const configureActorScript = `#!/bin/bash
set -euo pipefail

template="${STACKS_ATTACKNET_CONFIG_TEMPLATE:-/etc/stacks/config.toml}"
rendered="${STACKS_ATTACKNET_CONFIG:-/tmp/stacks-attacknet-config.toml}"
node_ip="${STACKS_ATTACKNET_NODE_IP:-}"
if [ -z "${node_ip}" ]; then
  node_ip="$(hostname -i | awk '{ print $1 }')"
fi
if ! awk -v ip="${node_ip}" 'BEGIN {
  count = split(ip, octets, ".")
  if (count != 4) exit 1
  for (i = 1; i <= 4; i++) {
    if (octets[i] !~ /^[0-9]+$/ || octets[i] < 0 || octets[i] > 255) exit 1
  }
}' </dev/null; then
  echo "could not derive a numeric IPv4 address for this actor: ${node_ip:-empty}" >&2
  exit 1
fi
temporary="${rendered}.tmp.$$"
trap 'rm -f "${temporary}"' EXIT
service_map="${STACKS_ATTACKNET_SERVICE_MAP:-}"
while IFS= read -r line || [ -n "${line}" ]; do
  line="${line//__NODE_IP__/${node_ip}}"
  while IFS='=' read -r logical service; do
    [ -n "${logical}" ] || continue
    token="\${SERVICE:${logical}}"
    line="${line//$token/$service}"
  done <<<"${service_map}"
  printf '%s\n' "${line}"
done <"${template}" >"${temporary}"
if grep -qF '${SERVICE:' "${temporary}"; then
  echo "actor config contains an unknown logical service reference" >&2
  exit 1
fi
mv "${temporary}" "${rendered}"
trap - EXIT
exec "$@"
`

func serviceMapTemplate(network *attacknetv1beta1.StacksNetwork) string {
	names := make([]string, 0, len(network.Spec.Burnchain.Nodes)+len(network.Spec.Nodes)+len(network.Spec.RawActors))
	for _, node := range network.Spec.Burnchain.Nodes {
		names = append(names, node.Name)
	}
	for _, node := range network.Spec.Nodes {
		names = append(names, node.Name)
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			names = append(names, member.Name, member.NodeName)
			if member.Adversarial != nil {
				names = append(names, adversarial.ObserverName(member.Name))
			}
		}
	}
	if network.Spec.Enrollment != nil {
		names = append(names, network.Spec.Enrollment.Name)
	}
	for _, actor := range network.Spec.RawActors {
		names = append(names, actor.Name)
	}
	sort.Strings(names)
	lines := make([]string, len(names))
	for index, name := range names {
		lines[index] = name + "=${SERVICE:" + name + "}"
	}
	return strings.Join(lines, "\n")
}

const nakamotoEpochs = `
[[burnchain.epochs]]
epoch_name = "1.0"
start_height = 0
[[burnchain.epochs]]
epoch_name = "2.0"
start_height = 0
[[burnchain.epochs]]
epoch_name = "2.05"
start_height = 203
[[burnchain.epochs]]
epoch_name = "2.1"
start_height = 204
[[burnchain.epochs]]
epoch_name = "2.2"
start_height = 206
[[burnchain.epochs]]
epoch_name = "2.3"
start_height = 207
[[burnchain.epochs]]
epoch_name = "2.4"
start_height = 208
[[burnchain.epochs]]
epoch_name = "2.5"
start_height = 209
[[burnchain.epochs]]
epoch_name = "3.0"
start_height = 223
[[burnchain.epochs]]
epoch_name = "3.1"
start_height = 224
[[burnchain.epochs]]
epoch_name = "3.2"
start_height = 225
[[burnchain.epochs]]
epoch_name = "3.3"
start_height = 226
[[burnchain.epochs]]
epoch_name = "3.4"
start_height = 227
[[burnchain.epochs]]
epoch_name = "4.0"
start_height = 1000005
`

func nakamotoNodeConfig(network *attacknetv1beta1.StacksNetwork, context profileContext, generated attacknetv1beta1.GeneratedConfigSpec) string {
	seed := generated.Seed
	if seed == "" {
		digest := sha256.Sum256([]byte(network.Name + ":" + context.actor))
		seed = hex.EncodeToString(digest[:])
	}
	miner := context.role == "miner"
	stacker := context.signerName != ""
	bootstrap := append([]string(nil), generated.BootstrapPeers...)
	if len(bootstrap) == 0 {
		bootstrap = append(bootstrap, network.Spec.Defaults.BootstrapPeers...)
	}
	sort.Strings(bootstrap)
	bootstrapLine := ""
	if len(bootstrap) > 0 {
		bootstrapLine = fmt.Sprintf("bootstrap_node = %q\n", strings.Join(bootstrap, ","))
	}
	dispatch := generated.EventDispatcher
	if dispatch == "" {
		dispatch = context.eventDispatcher
	}
	if dispatch == "" {
		dispatch = "queued"
	}
	observer := ""
	if context.signerName != "" {
		observer = fmt.Sprintf("\n[[events_observer]]\nendpoint = \"${SERVICE:%s}:30000\"\nevents_keys = [\"stackerdb\", \"block_proposal\", \"burn_blocks\"]\n", context.signerName)
	}
	return fmt.Sprintf("[node]\nname = %q\nrpc_bind = \"0.0.0.0:20443\"\np2p_bind = \"0.0.0.0:20444\"\ndata_url = \"http://__NODE_IP__:20443\"\np2p_address = \"__NODE_IP__:20444\"\nprometheus_bind = \"0.0.0.0:20446\"\nworking_dir = \"/data/node\"\nseed = %q\nlocal_peer_seed = %q\nminer = %t\nstacker = %t\nevent_dispatcher_blocking = %t\nevent_dispatcher_queue_size = 1000\nuse_test_genesis_chainstate = true\npox_sync_sample_secs = 0\nwait_time_for_blocks = 0\nwait_time_for_microblocks = 0\nmine_microblocks = false\n%s\n[connection_options]\npublic_ip_address = \"__NODE_IP__:20444\"\nprivate_neighbors = true\nwalk_interval = 5\ninv_sync_interval = 5\ndownload_interval = 1\nauth_token = \"12345\"\n%s\n[burnchain]\nchain = \"bitcoin\"\nmode = \"nakamoto-neon\"\npoll_time_secs = 1\nmagic_bytes = \"T3\"\npox_prepare_length = 5\npox_reward_length = 20\nburn_fee_cap = 20000\npeer_host = \"${SERVICE:%s}\"\npeer_port = %d\nrpc_port = %d\nrpc_ssl = false\nusername = \"devnet\"\npassword = \"devnet\"\ntimeout = 30\n%s%s", "attacknet-"+context.actor, seed, seed, miner, stacker, dispatch == "blocking", bootstrapLine, observer, context.burnchainNode, context.burnchainP2PPort, context.burnchainRPCPort, nakamotoEpochs, renderStacksGenesis(network.Spec.Genesis))
}

func bitcoinNodeByName(network *attacknetv1beta1.StacksNetwork, name string) attacknetv1beta1.BitcoinNodeSpec {
	for _, node := range network.Spec.Burnchain.Nodes {
		if node.Name == name {
			return node
		}
	}
	return attacknetv1beta1.BitcoinNodeSpec{}
}

func renderStacksGenesis(genesis *attacknetv1beta1.StacksGenesisSpec) string {
	if genesis == nil {
		return ""
	}
	var builder strings.Builder
	if genesis.PoX5 != nil {
		fmt.Fprintf(&builder, "\npox_5_sbtc_contract = %q\npox_5_sbtc_registry_contract = %q\n", genesis.PoX5.SbtcContract, genesis.PoX5.SbtcRegistryContract)
	}
	balances := append([]attacknetv1beta1.GenesisBalanceSpec(nil), genesis.Balances...)
	sort.Slice(balances, func(i, j int) bool { return balances[i].Address < balances[j].Address })
	for _, balance := range balances {
		fmt.Fprintf(&builder, "\n[[ustx_balance]]\naddress = %q\namount = %d\n", balance.Address, balance.Amount)
	}
	return builder.String()
}

func applyWorkload(actor *attacknetv1alpha1.ActorSpec, workload *attacknetv1beta1.WorkloadPolicy) {
	if workload == nil {
		return
	}
	actor.Storage = compileStorage(workload.Storage)
	actor.Resources = copyResourceRequirements(workload.Resources)
	actor.NodeSelector = copyStringMap(workload.NodeSelector)
	actor.Affinity = copyAffinity(workload.Affinity)
	actor.Tolerations = append([]corev1.Toleration(nil), workload.Tolerations...)
	actor.TopologySpreadConstraints = append([]corev1.TopologySpreadConstraint(nil), workload.TopologySpreadConstraints...)
	actor.TerminationGracePeriodSeconds = copyInt64(workload.TerminationGracePeriodSeconds)
	actor.RuntimeExposure = workload.RuntimeExposure
	actor.Telemetry = compileTelemetry(workload.Telemetry)
	actor.Probe = compileProbe(workload.Probe)
}

func applyAdvanced(actor *attacknetv1alpha1.ActorSpec, advanced *attacknetv1beta1.AdvancedWorkloadOverride) {
	if advanced == nil {
		return
	}
	if len(advanced.Command) > 0 {
		actor.Command = append([]string(nil), advanced.Command...)
	}
	if len(advanced.Args) > 0 {
		actor.Args = append([]string(nil), advanced.Args...)
	}
	actor.Env = append(actor.Env, advanced.Env...)
	actor.WorkingDir = advanced.WorkingDir
	actor.ReadinessProbe = advanced.ReadinessProbe.DeepCopy()
	actor.LivenessProbe = advanced.LivenessProbe.DeepCopy()
	actor.StartupProbe = advanced.StartupProbe.DeepCopy()
	actor.PodSecurityContext = advanced.PodSecurityContext.DeepCopy()
	actor.ContainerSecurityContext = advanced.ContainerSecurityContext.DeepCopy()
	actor.Labels = copyStringMap(advanced.Labels)
	actor.Annotations = copyStringMap(advanced.Annotations)
}

func compileStorage(value *attacknetv1beta1.StorageSpec) *attacknetv1alpha1.StorageSpec {
	if value == nil {
		return nil
	}
	return &attacknetv1alpha1.StorageSpec{Enabled: value.Enabled, Size: value.Size, MountPath: value.MountPath, StorageClassName: value.StorageClassName, AccessModes: append([]corev1.PersistentVolumeAccessMode(nil), value.AccessModes...)}
}

func compileTelemetry(value *attacknetv1beta1.TelemetrySpec) *attacknetv1alpha1.TelemetrySpec {
	if value == nil {
		return nil
	}
	result := &attacknetv1alpha1.TelemetrySpec{Enabled: value.Enabled, Image: value.Image, ImagePullPolicy: value.ImagePullPolicy, Resources: copyResourceRequirements(value.Resources), MetricsPort: value.MetricsPort, ExporterEndpoint: value.ExporterEndpoint}
	if value.TokenSecretRef != nil {
		result.TokenSecretRef = &attacknetv1alpha1.SecretKeyReference{Name: value.TokenSecretRef.Name, Key: value.TokenSecretRef.Key}
	}
	return result
}

func compileProbe(value *attacknetv1beta1.ProbeSpec) *attacknetv1alpha1.ProbeSpec {
	if value == nil {
		return nil
	}
	services := make([]attacknetv1alpha1.ProbeService, 0, len(value.AdditionalServices))
	for _, service := range value.AdditionalServices {
		ports := make([]attacknetv1alpha1.ProbePort, 0, len(service.Ports))
		for _, port := range service.Ports {
			ports = append(ports, attacknetv1alpha1.ProbePort{Name: port.Name, Port: port.Port})
		}
		services = append(services, attacknetv1alpha1.ProbeService{Name: service.Name, ServiceName: service.ServiceName, Ports: ports})
	}
	return &attacknetv1alpha1.ProbeSpec{Enabled: value.Enabled, Image: value.Image, ImagePullPolicy: value.ImagePullPolicy, Resources: copyResourceRequirements(value.Resources), AdditionalServices: services}
}

func copyResourceRequirements(value *corev1.ResourceRequirements) *corev1.ResourceRequirements {
	if value == nil {
		return nil
	}
	return value.DeepCopy()
}

func copyAffinity(value *corev1.Affinity) *corev1.Affinity {
	if value == nil {
		return nil
	}
	return value.DeepCopy()
}

func copyInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validateV1Beta1Network(network *attacknetv1beta1.StacksNetwork) error {
	if network == nil {
		return fmt.Errorf("network is required")
	}
	if network.Name == "" || network.Namespace == "" || network.UID == "" {
		return fmt.Errorf("metadata.name, metadata.namespace, and metadata.uid are required")
	}
	if err := burnchaintopology.Validate(network); err != nil {
		return err
	}
	if genesis := network.Spec.Genesis; genesis != nil {
		if genesis.PoX5 != nil && (genesis.PoX5.SbtcContract == "" || genesis.PoX5.SbtcRegistryContract == "") {
			return fmt.Errorf("spec.genesis.pox5 requires both sBTC contract identifiers")
		}
		addresses := make(map[string]struct{}, len(genesis.Balances))
		for _, balance := range genesis.Balances {
			if balance.Address == "" || balance.Amount <= 0 {
				return fmt.Errorf("spec.genesis.balances require non-empty addresses and positive amounts")
			}
			if _, exists := addresses[balance.Address]; exists {
				return fmt.Errorf("spec.genesis.balances contains duplicate address %q", balance.Address)
			}
			addresses[balance.Address] = struct{}{}
		}
	}
	if err := validateV1Beta1Telemetry(network); err != nil {
		return err
	}
	names := map[string]string{}
	addName := func(name, role string) error {
		if name == "" {
			return fmt.Errorf("%s actor name is required", role)
		}
		if existing, found := names[name]; found {
			return fmt.Errorf("duplicate actor name %q used by %s and %s", name, existing, role)
		}
		names[name] = role
		return nil
	}
	for _, node := range network.Spec.Burnchain.Nodes {
		if err := addName(node.Name, "burnchain"); err != nil {
			return err
		}
	}
	for _, node := range network.Spec.Nodes {
		if err := addName(node.Name, string(node.Role)); err != nil {
			return err
		}
		if node.Role != attacknetv1beta1.StacksNodeMiner && node.Role != attacknetv1beta1.StacksNodeFollower && node.Role != attacknetv1beta1.StacksNodeAdversary {
			return fmt.Errorf("node %q has unsupported role %q", node.Name, node.Role)
		}
	}
	indexes := map[int32]string{}
	for _, set := range network.Spec.SignerSets {
		if set.Name == "" {
			return fmt.Errorf("signer set name is required")
		}
		for _, member := range set.Members {
			if err := addName(member.Name, "signer"); err != nil {
				return err
			}
			if err := addName(member.NodeName, "signer-node"); err != nil {
				return err
			}
			if member.Index < 1 {
				return fmt.Errorf("signer %q index must be positive", member.Name)
			}
			if previous, found := indexes[member.Index]; found {
				return fmt.Errorf("signer index %d is shared by %q and %q", member.Index, previous, member.Name)
			}
			indexes[member.Index] = member.Name
			if member.Weight <= 0 {
				return fmt.Errorf("signer %q weight must be positive", member.Name)
			}
			if member.Adversarial != nil {
				if member.SignerImage == "" {
					return fmt.Errorf("adversarial signer %q requires an explicit signerImage", member.Name)
				}
				if _, err := adversarial.Normalize(member.Adversarial); err != nil {
					return fmt.Errorf("signer %q adversarial policy: %w", member.Name, err)
				}
				observerName := adversarial.ObserverName(member.Name)
				if err := addName(observerName, "adversarial observer"); err != nil {
					return err
				}
				if member.SignerAdvanced != nil {
					for _, variable := range member.SignerAdvanced.Env {
						if variable.Name == "STACKS_SIGNER_ATTACKNET_POLICY" || variable.Name == "STACKS_SIGNER_ATTACKNET_POLICY_DIGEST" {
							return fmt.Errorf("adversarial signer %q cannot override managed environment %q", member.Name, variable.Name)
						}
					}
				}
			}
		}
	}
	if enrollment := network.Spec.Enrollment; enrollment != nil {
		if err := addName(enrollment.Name, "signer enrollment"); err != nil {
			return err
		}
		if role, found := names[enrollment.NodeRef]; !found || (role != string(attacknetv1beta1.StacksNodeMiner) && role != string(attacknetv1beta1.StacksNodeFollower) && role != string(attacknetv1beta1.StacksNodeAdversary)) {
			return fmt.Errorf("signer enrollment %q references unknown Stacks node %q", enrollment.Name, enrollment.NodeRef)
		}
		secret := enrollment.CredentialsSecretRef
		if secret.Name == "" || secret.KeysKey == "" || secret.AddressesKey == "" {
			return fmt.Errorf("signer enrollment %q requires credential Secret name, keysKey, and addressesKey", enrollment.Name)
		}
		if enrollment.Advanced != nil {
			reserved := map[string]struct{}{
				"STACKS_CORE_RPC_HOST": {}, "STACKS_CORE_RPC_PORT": {},
				"STACKING_KEYS": {}, "STACKING_ADDRESSES": {},
				"STACKING_CYCLES": {}, "POX5_STACKING_CYCLES": {},
				"POX5_RENEWAL_WINDOW_CYCLES": {}, "STACKING_INTERVAL": {},
				"EPOCH_4_FIXTURE_DEPLOY_HEIGHT": {},
			}
			for _, variable := range enrollment.Advanced.Env {
				if _, found := reserved[variable.Name]; found {
					return fmt.Errorf("signer enrollment %q advanced environment cannot override managed variable %q", enrollment.Name, variable.Name)
				}
			}
		}
	}
	for _, raw := range network.Spec.RawActors {
		if err := addName(raw.Name, "raw actor"); err != nil {
			return err
		}
		if raw.Advanced == nil {
			return fmt.Errorf("raw actor %q requires explicit advanced workload configuration", raw.Name)
		}
	}
	if len(names) == 0 || len(names) > 100 {
		return fmt.Errorf("compiled topology must contain between 1 and 100 actors")
	}
	return nil
}
