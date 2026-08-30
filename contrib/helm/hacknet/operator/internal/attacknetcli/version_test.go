package attacknetcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/versionmatrix"
)

func TestVersionRenderCommandsConsumeOneSealedDescriptor(t *testing.T) {
	descriptor := versionDescriptorFixture(t)
	directory := t.TempDir()
	descriptorPath := filepath.Join(directory, "descriptor.json")
	encoded, err := versionmatrix.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	networkPath := filepath.Join(directory, "network.yaml")
	network := `apiVersion: testing.stacks.org/v1beta1
kind: StacksNetwork
metadata:
  name: network
spec:
  defaults:
    nodeImage: baseline:sealed
    signerImage: baseline:sealed
    bitcoinImage: bitcoin:sealed
  burnchain:
    policyRef: {name: clock}
    nodes:
      - name: bitcoin-1
        config:
          generated: {profile: bitcoin-regtest/v1}
  nodes:
    - name: miner-1
      role: miner
      burnchainNodeRef: bitcoin-1
      config:
        secretRef: {name: miner-config, key: config.toml}
`
	if err := os.WriteFile(networkPath, []byte(network), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"static", []string{"version", "render-static", "--descriptor", descriptorPath, "--network", networkPath}, "kind: StacksNetwork"},
		{"upgrade", []string{"version", "render-upgrade", "--descriptor", descriptorPath, "--namespace", "experiment"}, "kind: UpgradeCampaign"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			app := NewApp(&fakeBackend{}, "experiment", strings.NewReader(""), stdout, stderr)
			if code := app.Run(context.Background(), test.args); code != 0 {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) || !strings.Contains(stdout.String(), "sha256:aaaaaaaa") {
				t.Fatalf("rendered output is not descriptor-bound: %s", stdout.String())
			}
			if test.name == "upgrade" && !strings.Contains(stdout.String(), "template: true") {
				t.Fatalf("rendered upgrade is not an inert run-catalog template: %s", stdout.String())
			}
		})
	}
}

func TestVersionRenderUpgradeCanRenderDirectCampaign(t *testing.T) {
	directory := t.TempDir()
	descriptorPath := filepath.Join(directory, "descriptor.json")
	encoded, err := versionmatrix.Marshal(versionDescriptorFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(&fakeBackend{}, "experiment", strings.NewReader(""), stdout, stderr)
	if code := app.Run(context.Background(), []string{"version", "render-upgrade", "--descriptor", descriptorPath, "--template=false"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "template: true") {
		t.Fatalf("direct upgrade was rendered as an inert template: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "status:") {
		t.Fatalf("rendered desired state contains controller-owned status: %s", stdout.String())
	}
	if _, kind, err := DecodeSubmission(stdout.Bytes(), "experiment"); err != nil || kind.Name != "UpgradeCampaign" {
		t.Fatalf("rendered upgrade is not directly submittable: kind=%s err=%v\n%s", kind.Name, err, stdout.String())
	}
}

func TestVersionPrepareRejectsUnknownPlanFieldsBeforeExecution(t *testing.T) {
	directory := t.TempDir()
	plan := filepath.Join(directory, "plan.yaml")
	if err := os.WriteFile(plan, []byte("schemaVersion: stacks-attacknet-version-plan/v1\nmatrixId: demo\nplatform: linux/arm64\nunknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(&fakeBackend{}, "experiment", strings.NewReader(""), stdout, stderr)
	app.CommandRunner = &recordingRunner{}
	if code := app.Run(context.Background(), []string{"version", "prepare", "--file", plan, "--workspace", filepath.Join(directory, "workspace"), "--output", filepath.Join(directory, "descriptor.json")}); code != 1 {
		t.Fatalf("exit %d, want input failure: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("strict plan decoder did not explain the rejection: %s", stderr.String())
	}
}

func TestVerifyDescriptorImportsRequiresEveryExactRuntimeIdentity(t *testing.T) {
	descriptor := versionDescriptorFixture(t)
	digest := descriptor.Profiles[0].ImageID
	receipt := KindImageLoadResult{
		Outcome: "Loaded", Nodes: []KindNode{{Name: "worker-1"}},
		Images: []KindImageImport{{Node: "worker-1", RequestedRef: "candidate:sealed", RuntimeImageID: digest, Verified: true}},
	}
	if err := verifyDescriptorImports(descriptor, receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Images[0].RuntimeImageID = "sha256:" + strings.Repeat("b", 64)
	if err := verifyDescriptorImports(descriptor, receipt); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("runtime identity substitution was accepted: %v", err)
	}
	receipt.Images = nil
	if err := verifyDescriptorImports(descriptor, receipt); err == nil || !strings.Contains(err.Error(), "every target node") {
		t.Fatalf("incomplete import receipt was accepted: %v", err)
	}
}

func TestDescriptorImageIdentitiesDeduplicatesSharedImages(t *testing.T) {
	descriptor := versionDescriptorFixture(t)
	shared := descriptor.Profiles[0]
	shared.Name = "shared"
	descriptor.Profiles = append(descriptor.Profiles, shared)
	refs, identities, err := descriptorImageIdentities(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || len(identities) != 1 {
		t.Fatalf("shared image was not deduplicated: refs=%#v identities=%#v", refs, identities)
	}
	descriptor.Profiles[1].ImageID = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := descriptorImageIdentities(descriptor); err == nil {
		t.Fatal("one image reference was accepted with conflicting runtime identities")
	}
}

func versionDescriptorFixture(t *testing.T) versionmatrix.Descriptor {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor := versionmatrix.Descriptor{
		SchemaVersion: versionmatrix.DescriptorSchema, MatrixID: "matrix", Platform: "linux/arm64", PlanDigest: digest,
		Profiles: []versionmatrix.ResolvedProfile{{
			Name: "candidate", SourceKind: "prebuilt", Image: "candidate:sealed", ImageID: digest,
			ProvenanceDigest: digest, ConfigDigest: digest, ConfigSmoke: "externally-digest-bound",
		}},
		Assignments: []versionmatrix.Assignment{{Actor: "miner-1", Profile: "candidate"}},
		Assignment:  versionmatrix.AssignmentReceipt{Algorithm: versionmatrix.AssignmentAlgorithm, Actors: []versionmatrix.ActorPlan{{Name: "miner-1", Role: "miner"}}},
		Upgrade: &versionmatrix.UpgradePlan{
			Name: "roll", NetworkRef: "network", RollbackOnFailure: true,
			Safety: attacknetv1beta1.UpgradeSafetySpec{MaxParallelActors: 1, MaxSignerWeightPercent: 100, MaxMinerPercent: 100},
			Stages: []versionmatrix.UpgradeStagePlan{{Name: "candidate", StableFor: "1s", Deadline: "1m", Actors: []versionmatrix.Assignment{{Actor: "miner-1", Profile: "candidate"}}}},
		},
	}
	view := descriptor
	view.Digest = ""
	var err error
	descriptor.Digest, err = canonical.ArtifactDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
