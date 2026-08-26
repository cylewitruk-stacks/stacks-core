package attacknetcli

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const policyYAML = `apiVersion: testing.stacks.org/v1beta1
kind: BurnchainPolicy
metadata:
  name: clock
spec:
  networkRef: net
  bitcoinNodeRef: bitcoin
  cadence: 1m
  destinations:
    - walletName: miner
      address: bcrt1qexample
`

func TestDecodeSubmissionYAMLAndJSONAreCanonical(t *testing.T) {
	fromYAML, yamlKind, err := DecodeSubmission([]byte(policyYAML), "experiment")
	if err != nil {
		t.Fatal(err)
	}
	jsonInput := `{"apiVersion":"testing.stacks.org/v1beta1","kind":"BurnchainPolicy","metadata":{"name":"clock","namespace":"experiment"},"spec":{"bitcoinNodeRef":"bitcoin","cadence":"1m","destinations":[{"address":"bcrt1qexample","walletName":"miner"}],"networkRef":"net"}}`
	fromJSON, jsonKind, err := DecodeSubmission([]byte(jsonInput), "experiment")
	if err != nil {
		t.Fatal(err)
	}
	if yamlKind.Name != jsonKind.Name || fromYAML.GetNamespace() != "experiment" {
		t.Fatalf("kind or namespace mismatch: %#v %#v", yamlKind, fromYAML.Object)
	}
	if _, present := fromYAML.Object["status"]; present {
		t.Fatalf("submission synthesized controller-owned status: %#v", fromYAML.Object)
	}
	metadata, _, err := unstructured.NestedMap(fromYAML.Object, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"} {
		if _, present := metadata[field]; present {
			t.Fatalf("submission synthesized server metadata %s: %#v", field, metadata)
		}
	}
	yamlDigest, err := canonical.ArtifactDigest(fromYAML.Object)
	if err != nil {
		t.Fatal(err)
	}
	jsonDigest, err := canonical.ArtifactDigest(fromJSON.Object)
	if err != nil {
		t.Fatal(err)
	}
	if yamlDigest != jsonDigest {
		t.Fatalf("YAML/JSON digest mismatch: %s != %s", yamlDigest, jsonDigest)
	}
}

func TestDecodeSubmissionFailsClosed(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"duplicate", strings.Replace(policyYAML, "kind: BurnchainPolicy", "kind: BurnchainPolicy\nkind: AttacknetRun", 1), "already set"},
		{"status", policyYAML + "status: {}\n", "must omit"},
		{"server metadata", strings.Replace(policyYAML, "name: clock", "name: clock\n  resourceVersion: '3'", 1), "server-assigned"},
		{"unknown kind", strings.Replace(policyYAML, "BurnchainPolicy", "SomethingElse", 1), "unsupported"},
		{"unknown field", strings.Replace(policyYAML, "  networkRef: net", "  networkRef: net\n  surprise: true", 1), "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := DecodeSubmission([]byte(test.input), "experiment")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDecodeSubmissionRejectsStructurallyInvalidFaultCampaign(t *testing.T) {
	input := `apiVersion: testing.stacks.org/v1beta1
kind: FaultCampaign
metadata:
  name: invalid-campaign
spec:
  networkRef: network
  stages:
    - id: invalid
      faults:
        - id: mismatch
          target:
            actors: [miner-1]
          fault:
            type: dns
            action: pod-kill
            mode: all
            duration: 1m
            parameters:
              patterns: [example.invalid]
  safety:
    maxUnavailableSignerBasisPoints: 10000
    maxUnavailableMinerBasisPoints: 10000
    maxConcurrentFaults: 1
    allowQuorumLoss: false
    allowBurnchain: false
    allowExtendedDuration: false
    allowExtremeSeverity: false
    allowMinerMajorityOutage: false
    allowUnenrolledNetworkTargets: false
`
	_, _, err := DecodeSubmission([]byte(input), "experiment")
	if err == nil || !strings.Contains(err.Error(), "unsupported dns action") {
		t.Fatalf("got %v, want shared static validation rejection", err)
	}
}

func TestDecodeSubmissionHonorsAnExplicitDocumentNamespace(t *testing.T) {
	input := strings.Replace(policyYAML, "name: clock", "name: clock\n  namespace: other", 1)
	object, _, err := DecodeSubmission([]byte(input), "experiment")
	if err != nil {
		t.Fatal(err)
	}
	if object.GetNamespace() != "other" {
		t.Fatalf("namespace = %q, want document namespace", object.GetNamespace())
	}
}

func TestLookupKindCatalogIsClosed(t *testing.T) {
	kinds := Kinds()
	if len(kinds) != 4 {
		t.Fatalf("got %d kinds", len(kinds))
	}
	for _, kind := range kinds {
		resolved, err := LookupKind(kind.Plural)
		if err != nil || resolved.Name != kind.Name {
			t.Fatalf("plural lookup failed for %s: %#v %v", kind.Name, resolved, err)
		}
	}
	if _, err := LookupKind("Pod"); err == nil {
		t.Fatal("raw Kubernetes kind was accepted")
	}
}
