package document

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestDecodeOneYAMLAndJSONHaveIdenticalCanonicalDigest(t *testing.T) {
	yamlInput := []byte(`
apiVersion: testing.stacks.org/v1beta1
kind: BurnchainPolicy
metadata:
  name: clock
spec:
  networkRef: net
  bitcoinNodeRef: bitcoin-1
  bootstrapHeight: 202
  cadence: 1m0s
`)
	jsonInput := []byte(`{"kind":"BurnchainPolicy","apiVersion":"testing.stacks.org/v1beta1","spec":{"cadence":"1m0s","bootstrapHeight":202,"bitcoinNodeRef":"bitcoin-1","networkRef":"net"},"metadata":{"name":"clock"}}`)
	var fromYAML, fromJSON attacknetv1beta1.BurnchainPolicy
	if err := DecodeOne(yamlInput, &fromYAML); err != nil {
		t.Fatal(err)
	}
	if err := DecodeOne(jsonInput, &fromJSON); err != nil {
		t.Fatal(err)
	}
	yamlDigest, err := canonical.ArtifactDigest(fromYAML)
	if err != nil {
		t.Fatal(err)
	}
	jsonDigest, err := canonical.ArtifactDigest(fromJSON)
	if err != nil {
		t.Fatal(err)
	}
	if yamlDigest != jsonDigest {
		t.Fatalf("semantic YAML/JSON digest mismatch: %s != %s", yamlDigest, jsonDigest)
	}
}

func TestDecodeOneFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"duplicate", "apiVersion: testing.stacks.org/v1beta1\nkind: BurnchainPolicy\nkind: StacksNetwork\n", "already set"},
		{"unknown", "apiVersion: testing.stacks.org/v1beta1\nkind: BurnchainPolicy\nmetadata: {name: clock}\nspec:\n  networkRef: net\n  bitcoinNodeRef: bitcoin\n  cadence: 1m\n  surprise: true\n", "unknown field"},
		{"multiple", "kind: BurnchainPolicy\n---\nkind: StacksNetwork\n", "exactly one"},
		{"empty", "# comment only\n", "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value attacknetv1beta1.BurnchainPolicy
			err := DecodeOne([]byte(test.input), &value)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestEncodeYAMLRoundTrip(t *testing.T) {
	input := attacknetv1beta1.BurnchainPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "clock"},
		Spec:       attacknetv1beta1.BurnchainPolicySpec{NetworkRef: "net", BitcoinNodeRef: "bitcoin", Cadence: metav1.Duration{}},
	}
	encoded, err := EncodeYAML(input)
	if err != nil {
		t.Fatal(err)
	}
	var output attacknetv1beta1.BurnchainPolicy
	if err := DecodeOne(encoded, &output); err != nil {
		t.Fatal(err)
	}
	if output.Name != input.Name || output.Spec.NetworkRef != input.Spec.NetworkRef {
		t.Fatalf("round trip mismatch: %#v", output)
	}
}
