package topology

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCompileV1Beta1DomainTopology(t *testing.T) {
	network := betaNetworkFixture()
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Spec.Actors) != 5 {
		t.Fatalf("expected bitcoin, miner, signer node, signer and raw actor; got %d", len(compiled.Spec.Actors))
	}
	want := []struct {
		name string
		role string
	}{{"bitcoin-1", "burnchain"}, {"miner-1", "miner"}, {"signer-node-1", "companion"}, {"signer-1", "signer"}, {"observer", "infrastructure"}}
	for index, expected := range want {
		if compiled.Spec.Actors[index].Name != expected.name || compiled.Spec.Actors[index].Role != expected.role {
			t.Fatalf("actor %d mismatch: %#v", index, compiled.Spec.Actors[index])
		}
	}
	if compiled.Spec.Actors[1].Dependencies[0].Actor != "bitcoin-1" {
		t.Fatalf("miner burnchain dependency was not compiled: %#v", compiled.Spec.Actors[1].Dependencies)
	}
	if compiled.Spec.Actors[2].Dependencies[1].Actor != "signer-1" {
		t.Fatalf("signer-node event dependency was not compiled: %#v", compiled.Spec.Actors[2].Dependencies)
	}
	if compiled.Spec.Actors[3].SignerWeight == nil || *compiled.Spec.Actors[3].SignerWeight != 10 {
		t.Fatalf("signer weight was not preserved: %#v", compiled.Spec.Actors[3].SignerWeight)
	}
	if compiled.Spec.Actors[2].SignerIndex == nil || *compiled.Spec.Actors[2].SignerIndex != 1 ||
		compiled.Spec.Actors[2].SignerWeight == nil || *compiled.Spec.Actors[2].SignerWeight != 10 ||
		compiled.Spec.Actors[2].SignerPublicKey != compiled.Spec.Actors[3].SignerPublicKey {
		t.Fatalf("signer-node identity was not preserved: %#v", compiled.Spec.Actors[2])
	}
}

func TestCompileV1Beta1RejectsAmbiguousAndInvalidTopology(t *testing.T) {
	t.Run("missing burnchain policy", func(t *testing.T) {
		network := betaNetworkFixture()
		network.Spec.Burnchain.PolicyRef.Name = ""
		if _, err := CompileV1Beta1(network); err == nil {
			t.Fatal("missing burnchain policy was accepted")
		}
	})
	t.Run("duplicate actor", func(t *testing.T) {
		network := betaNetworkFixture()
		network.Spec.Nodes[0].Name = "bitcoin-1"
		if _, err := CompileV1Beta1(network); err == nil {
			t.Fatal("duplicate cross-kind actor name was accepted")
		}
	})
	t.Run("unknown burnchain", func(t *testing.T) {
		network := betaNetworkFixture()
		network.Spec.Nodes[0].BurnchainNodeRef = "missing"
		if _, err := CompileV1Beta1(network); err == nil {
			t.Fatal("unknown burnchain binding was accepted")
		}
	})
	t.Run("multiple config sources", func(t *testing.T) {
		network := betaNetworkFixture()
		network.Spec.Nodes[0].Config.SecretRef = &attacknetv1beta1.ConfigObjectRef{Name: "also-secret"}
		if _, err := CompileV1Beta1(network); err == nil {
			t.Fatal("multiple config sources were accepted")
		}
	})
	t.Run("raw actor without explicit advanced boundary", func(t *testing.T) {
		network := betaNetworkFixture()
		network.Spec.RawActors[0].Advanced = nil
		if _, err := CompileV1Beta1(network); err == nil {
			t.Fatal("unmarked raw actor was accepted")
		}
	})
}

func TestMarkBurnchainPolicyPendingPreservesInventoryButWithdrawsReady(t *testing.T) {
	status := attacknetv1beta1.StacksNetworkStatus{
		Phase: "Ready", InventoryReady: true, InventoryDigest: "sha256:inventory",
		Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 4, Reason: "AllActorsReady"}},
	}
	markBurnchainPolicyPending(&status, 4, "BurnchainPolicyNotReady", "bootstrap is running")
	if status.Phase != "Pending" || !status.InventoryReady || status.InventoryDigest != "sha256:inventory" {
		t.Fatalf("policy barrier corrupted admitted workload identity: %#v", status)
	}
	ready := findCondition(status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "BurnchainPolicyNotReady" {
		t.Fatalf("Ready condition = %#v", ready)
	}
}

func findCondition(conditions []metav1.Condition, kind string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == kind {
			return &conditions[index]
		}
	}
	return nil
}

func TestCompileV1Beta1GeneratedProfiles(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Burnchain.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "bitcoin-regtest/v1"}}
	network.Spec.Nodes[0].Role = attacknetv1beta1.StacksNodeFollower
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{
		Profile: "nakamoto-regtest-node/v1", Seed: "11", BootstrapPeers: []string{"peer-b", "peer-a"}, EventDispatcher: "blocking",
	}}
	network.Spec.SignerSets[0].Members[0].NodeConfig = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "nakamoto-regtest-node/v1"}}
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Spec.Actors[0].Config.Files["bitcoin.conf"] == "" || compiled.Spec.Actors[1].Config.Files["config.toml"] == "" {
		t.Fatal("generated profiles did not produce complete config files")
	}
	if compiled.Spec.Actors[1].Config.Key != "config.toml" || compiled.Spec.Actors[3].Config.Key != "config.toml" {
		t.Fatalf("config keys do not match executable command paths: node=%q signer=%q", compiled.Spec.Actors[1].Config.Key, compiled.Spec.Actors[3].Config.Key)
	}
	nodeConfig := compiled.Spec.Actors[1].Config.Files["config.toml"]
	for _, expected := range []string{
		`p2p_address = "__NODE_IP__:20444"`,
		`public_ip_address = "__NODE_IP__:20444"`,
		`epoch_name = "4.0"`,
		"private_neighbors = true",
	} {
		if !strings.Contains(nodeConfig, expected) {
			t.Fatalf("generated node config lacks %q:\n%s", expected, nodeConfig)
		}
	}
	if len(compiled.Spec.Actors[1].Command) == 0 || !strings.Contains(strings.Join(compiled.Spec.Actors[1].Command, " "), "__NODE_IP__") {
		t.Fatal("generated node profile does not fail-closed while resolving its advertised Pod address")
	}
	companionConfig := compiled.Spec.Actors[2].Config.Files["config.toml"]
	if !strings.Contains(companionConfig, `endpoint = "${SERVICE:signer-1}:30000"`) || !strings.Contains(companionConfig, "stacker = true") {
		t.Fatal("generated signer-node config lacks its signer observer or StackerDB subscription")
	}
	if !strings.Contains(nodeConfig, `bootstrap_node = "peer-a,peer-b"`) || !strings.Contains(nodeConfig, "event_dispatcher_blocking = true") {
		t.Fatal("typed generated-profile overlays were not applied deterministically")
	}
	second, err := CompileV1Beta1(network.DeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Spec.Actors[1].Config.Files["config.toml"] != second.Spec.Actors[1].Config.Files["config.toml"] {
		t.Fatal("generated profile is not deterministic")
	}
}

func TestCompileV1Beta1RequiresSecretBackedMinerAndSignerConfigs(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "nakamoto-regtest-node/v1"}}
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "Secret-backed config") {
		t.Fatalf("generated miner config error = %v", err)
	}
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{SecretRef: &attacknetv1beta1.ConfigObjectRef{Name: "miner-config", Key: "config.toml"}}
	network.Spec.SignerSets[0].Members[0].SignerConfig = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "nakamoto-regtest-node/v1"}}
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "Secret-backed config") {
		t.Fatalf("generated signer config error = %v", err)
	}
}

func TestCompileV1Beta1ExternalNodeConfigUsesOpaqueRuntimeTemplateWrapper(t *testing.T) {
	network := betaNetworkFixture()
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(compiled.Spec.Actors[1].Command, " ")
	if !strings.Contains(command, "__NODE_IP__") || !strings.Contains(command, "/tmp/stacks-attacknet-config.toml") {
		t.Fatalf("external node config lacks the in-Pod address wrapper: %v", compiled.Spec.Actors[1].Command)
	}
	if len(compiled.Spec.Actors[1].Env) != 2 || compiled.Spec.Actors[1].Env[0].Name != "STACKS_ATTACKNET_CONFIG_TEMPLATE" || compiled.Spec.Actors[1].Env[0].Value != "/etc/stacks/config.toml" || compiled.Spec.Actors[1].Env[1].Name != "STACKS_ATTACKNET_SERVICE_MAP" {
		t.Fatalf("external node config lacks its logical Service map: %#v", compiled.Spec.Actors[1].Env)
	}
	for _, expected := range []string{"bitcoin-1=${SERVICE:bitcoin-1}", "miner-1=${SERVICE:miner-1}", "signer-node-1=${SERVICE:signer-node-1}"} {
		if !strings.Contains(compiled.Spec.Actors[1].Env[1].Value, expected) {
			t.Errorf("logical Service map lacks %q: %q", expected, compiled.Spec.Actors[1].Env[1].Value)
		}
	}
	signer := compiled.Spec.Actors[3]
	if command := strings.Join(signer.Command, " "); !strings.Contains(command, "stacks-signer") || !strings.Contains(command, "/tmp/stacks-attacknet-config.toml") {
		t.Fatalf("external signer config lacks the in-Pod template wrapper: %v", signer.Command)
	}
	if len(signer.Env) != 2 || signer.Env[0].Name != "STACKS_ATTACKNET_CONFIG_TEMPLATE" || signer.Env[0].Value != "/etc/stacks/config.toml" || signer.Env[1].Name != "STACKS_ATTACKNET_SERVICE_MAP" || !strings.Contains(signer.Env[1].Value, "signer-node-1=${SERVICE:signer-node-1}") {
		t.Fatalf("external signer config lacks its logical Service map: %#v", signer.Env)
	}
}

func TestConfigureActorScriptRendersAddressAndLogicalServices(t *testing.T) {
	directory := t.TempDir()
	template := filepath.Join(directory, "config.toml")
	rendered := filepath.Join(directory, "rendered.toml")
	contents := "node_ip = \"__NODE_IP__:20444\"\nrpc = \"${SERVICE:bitcoin-1}:18443\"\npeer = \"${SERVICE:miner-1}:20444\"\n"
	if err := os.WriteFile(template, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "-ceu", configureActorScript, "--", "/usr/bin/true")
	command.Env = append(os.Environ(),
		"STACKS_ATTACKNET_CONFIG_TEMPLATE="+template,
		"STACKS_ATTACKNET_CONFIG="+rendered,
		"STACKS_ATTACKNET_NODE_IP=10.42.0.7",
		"STACKS_ATTACKNET_SERVICE_MAP=bitcoin-1=network-bitcoin-1\nminer-1=network-miner-1",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("configure node: %v: %s", err, output)
	}
	got, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	want := "node_ip = \"10.42.0.7:20444\"\nrpc = \"network-bitcoin-1:18443\"\npeer = \"network-miner-1:20444\"\n"
	if string(got) != want {
		t.Fatalf("rendered config = %q, want %q", got, want)
	}
}

func TestConfigureActorScriptRejectsUnknownLogicalService(t *testing.T) {
	directory := t.TempDir()
	template := filepath.Join(directory, "config.toml")
	if err := os.WriteFile(template, []byte("peer = \"${SERVICE:missing}:20444\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "-ceu", configureActorScript, "--", "/usr/bin/true")
	command.Env = append(os.Environ(),
		"STACKS_ATTACKNET_CONFIG_TEMPLATE="+template,
		"STACKS_ATTACKNET_CONFIG="+filepath.Join(directory, "rendered.toml"),
		"STACKS_ATTACKNET_NODE_IP=10.42.0.7",
		"STACKS_ATTACKNET_SERVICE_MAP=bitcoin-1=network-bitcoin-1",
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "unknown logical service reference") {
		t.Fatalf("configure node error = %v, output = %q", err, output)
	}
}

func TestCompileV1Beta1SignerEnrollmentUsesSecretCredentials(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Enrollment = &attacknetv1beta1.SignerEnrollmentSpec{
		Name: "stacker", Image: "stacker:test", NodeRef: "miner-1",
		CredentialsSecretRef: attacknetv1beta1.SignerEnrollmentSecretRef{
			Name: "stacker-credentials", KeysKey: "keys", AddressesKey: "addresses",
		},
	}
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	actor := compiled.Spec.Actors[4]
	if actor.Name != "stacker" || actor.Role != "infrastructure" || actor.Dependencies[0].Actor != "miner-1" {
		t.Fatalf("enrollment actor = %#v", actor)
	}
	values := map[string]corev1.EnvVar{}
	for _, value := range actor.Env {
		values[value.Name] = value
	}
	for name, key := range map[string]string{"STACKING_KEYS": "keys", "STACKING_ADDRESSES": "addresses"} {
		value := values[name]
		if value.ValueFrom == nil || value.ValueFrom.SecretKeyRef == nil || value.ValueFrom.SecretKeyRef.Name != "stacker-credentials" || value.ValueFrom.SecretKeyRef.Key != key {
			t.Fatalf("%s is not Secret-backed: %#v", name, value)
		}
	}
	if values["STACKING_KEYS"].Value != "" || values["STACKING_ADDRESSES"].Value != "" {
		t.Fatal("enrollment credentials were copied into plaintext environment values")
	}
}

func TestCompileV1Beta1SignerEnrollmentRejectsManagedEnvironmentOverride(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Enrollment = &attacknetv1beta1.SignerEnrollmentSpec{
		Name: "stacker", Image: "stacker:test", NodeRef: "miner-1",
		CredentialsSecretRef: attacknetv1beta1.SignerEnrollmentSecretRef{Name: "credentials", KeysKey: "keys", AddressesKey: "addresses"},
		Advanced:             &attacknetv1beta1.AdvancedWorkloadOverride{Env: []corev1.EnvVar{{Name: "STACKING_KEYS", Value: "plaintext"}}},
	}
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "cannot override managed variable") {
		t.Fatalf("managed environment override error = %v", err)
	}
}

func TestCompileV1Beta1GeneratedProfileUsesSelectedBurnchain(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Burnchain.Nodes = append(network.Spec.Burnchain.Nodes, attacknetv1beta1.BitcoinNodeSpec{
		Name:   "bitcoin-2",
		Config: attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "bitcoin-regtest/v1"}},
	})
	network.Spec.Nodes[0].BurnchainNodeRef = "bitcoin-2"
	network.Spec.Nodes[0].Role = attacknetv1beta1.StacksNodeFollower
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{
		Profile: "nakamoto-regtest-node/v1",
	}}
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	config := compiled.Spec.Actors[2].Config.Files["config.toml"]
	if !strings.Contains(config, `peer_host = "${SERVICE:bitcoin-2}"`) || strings.Contains(config, `peer_host = "${SERVICE:bitcoin-1}"`) {
		t.Fatalf("generated node config did not use selected burnchain node:\n%s", config)
	}
}

func TestCompileV1Beta1GeneratedProfileInheritsDefaultBootstrapPeers(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Defaults.BootstrapPeers = []string{"peer-b", "peer-a"}
	network.Spec.Nodes[0].Role = attacknetv1beta1.StacksNodeFollower
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{
		Profile: "nakamoto-regtest-node/v1",
	}}

	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	config := compiled.Spec.Actors[1].Config.Files["config.toml"]
	if !strings.Contains(config, `bootstrap_node = "peer-a,peer-b"`) {
		t.Fatalf("generated node config did not inherit sorted default bootstrap peers:\n%s", config)
	}

	network.Spec.Nodes[0].Config.Generated.BootstrapPeers = []string{"profile-peer"}
	compiled, err = CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	config = compiled.Spec.Actors[1].Config.Files["config.toml"]
	if !strings.Contains(config, `bootstrap_node = "profile-peer"`) || strings.Contains(config, "peer-a") {
		t.Fatalf("profile-local bootstrap peers did not override defaults:\n%s", config)
	}
}

func TestCompileV1Beta1GeneratedProfileRendersCanonicalNetworkGenesis(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Nodes[0].Role = attacknetv1beta1.StacksNodeFollower
	network.Spec.Nodes[0].Config = attacknetv1beta1.ConfigSource{Generated: &attacknetv1beta1.GeneratedConfigSpec{Profile: "nakamoto-regtest-node/v1"}}
	network.Spec.Genesis = &attacknetv1beta1.StacksGenesisSpec{
		PoX5: &attacknetv1beta1.PoX5GenesisSpec{SbtcContract: "STTEST.sbtc-token", SbtcRegistryContract: "STTEST.sbtc-registry"},
		Balances: []attacknetv1beta1.GenesisBalanceSpec{
			{Address: "STZ", Amount: 2},
			{Address: "STA", Amount: 1},
		},
	}

	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	config := compiled.Spec.Actors[1].Config.Files["config.toml"]
	for _, expected := range []string{
		`pox_5_sbtc_contract = "STTEST.sbtc-token"`,
		`pox_5_sbtc_registry_contract = "STTEST.sbtc-registry"`,
		"[[ustx_balance]]\naddress = \"STA\"\namount = 1",
		"[[ustx_balance]]\naddress = \"STZ\"\namount = 2",
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("generated node config lacks canonical genesis value %q:\n%s", expected, config)
		}
	}
	if strings.Index(config, `address = "STA"`) > strings.Index(config, `address = "STZ"`) {
		t.Fatal("genesis balances were not sorted deterministically")
	}

	network.Spec.Genesis.Balances = append(network.Spec.Genesis.Balances, attacknetv1beta1.GenesisBalanceSpec{Address: "STA", Amount: 3})
	if _, err := CompileV1Beta1(network); err == nil || !strings.Contains(err.Error(), "duplicate address") {
		t.Fatalf("duplicate genesis balance error = %v", err)
	}
}

func TestCompileV1Beta1BitcoinUsesResolvedExternalConfigPath(t *testing.T) {
	network := betaNetworkFixture()
	network.Spec.Burnchain.Nodes[0].Config = attacknetv1beta1.ConfigSource{SecretRef: &attacknetv1beta1.ConfigObjectRef{
		Name: "bitcoin-secret", Key: "custom.conf", MountPath: "/run/bitcoin-config",
	}}
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	if got := compiled.Spec.Actors[0].Args[0]; got != "-conf=/run/bitcoin-config/custom.conf" {
		t.Fatalf("bitcoin config argument = %q", got)
	}
}

func TestV1Beta1ResourcesAreOwnedByPublicResourceVersion(t *testing.T) {
	network := betaNetworkFixture()
	compiled, err := CompileV1Beta1(network)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := attacknetv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	resources, err := Render(compiled, scheme)
	if err != nil {
		t.Fatal(err)
	}
	bindV1Beta1Owner(resources, network)
	for _, object := range resources.Objects() {
		owner := metav1.GetControllerOf(object)
		if owner == nil || owner.APIVersion != attacknetv1beta1.GroupVersion.String() || owner.Kind != "StacksNetwork" || owner.UID != network.UID {
			t.Fatalf("resource %T/%s has incorrect public owner reference: %#v", object, object.GetName(), owner)
		}
	}
}

func TestV1Beta1RendererDefaultsBindTheInstalledProbeWithoutOverridingUserIntent(t *testing.T) {
	enabled := true
	network := &attacknetv1alpha1.StacksNetwork{Spec: attacknetv1alpha1.StacksNetworkSpec{
		Probe: &attacknetv1alpha1.ProbeSpec{Enabled: &enabled},
	}}
	applyV1Beta1RendererDefaults(network, "probe:immutable", corev1.PullNever)
	if network.Spec.Probe.Image != "probe:immutable" || network.Spec.Probe.ImagePullPolicy != corev1.PullNever {
		t.Fatalf("installed defaults were not applied: %#v", network.Spec.Probe)
	}
	network.Spec.Probe.Image = "probe:user"
	network.Spec.Probe.ImagePullPolicy = corev1.PullAlways
	applyV1Beta1RendererDefaults(network, "probe:other", corev1.PullIfNotPresent)
	if network.Spec.Probe.Image != "probe:user" || network.Spec.Probe.ImagePullPolicy != corev1.PullAlways {
		t.Fatalf("user probe settings were overwritten: %#v", network.Spec.Probe)
	}
}

func betaNetworkFixture() *attacknetv1beta1.StacksNetwork {
	configMap := func(name string) attacknetv1beta1.ConfigSource {
		return attacknetv1beta1.ConfigSource{ConfigMapRef: &attacknetv1beta1.ConfigObjectRef{Name: name, Key: "config.toml"}}
	}
	return &attacknetv1beta1.StacksNetwork{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "StacksNetwork"},
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid")},
		Spec: attacknetv1beta1.StacksNetworkSpec{
			Defaults:   attacknetv1beta1.NetworkDefaults{NodeImage: "node:current", SignerImage: "signer:current", BitcoinImage: "bitcoin:current", ImagePullPolicy: corev1.PullIfNotPresent},
			Burnchain:  attacknetv1beta1.BurnchainTopologySpec{PolicyRef: corev1.LocalObjectReference{Name: "clock"}, Nodes: []attacknetv1beta1.BitcoinNodeSpec{{Name: "bitcoin-1", Config: configMap("bitcoin-config")}}},
			Nodes:      []attacknetv1beta1.StacksNodeSpec{{Name: "miner-1", Role: attacknetv1beta1.StacksNodeMiner, BurnchainNodeRef: "bitcoin-1", Config: configMap("miner-config")}},
			SignerSets: []attacknetv1beta1.SignerSetSpec{{Name: "set-1", Members: []attacknetv1beta1.SignerMemberSpec{{Name: "signer-1", NodeName: "signer-node-1", Index: 1, Weight: 10, BurnchainNodeRef: "bitcoin-1", SignerConfig: attacknetv1beta1.ConfigSource{SecretRef: &attacknetv1beta1.ConfigObjectRef{Name: "signer-secret", Key: "config.toml"}}, NodeConfig: configMap("signer-node-config")}}}},
			RawActors:  []attacknetv1beta1.RawActorSpec{{Name: "observer", Role: "infrastructure", Image: "observer:current", Advanced: &attacknetv1beta1.AdvancedWorkloadOverride{Command: []string{"observer"}}}},
		},
	}
}
