package fuzzsession

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

func TestCapacityAdmissionIsSortedAndFailsClosed(t *testing.T) {
	policy := fuzzplan.CapacityPlan{
		MinimumNodeBytes: 100, MinimumImageBytes: 50,
		MinimumCorpusBytes: 200, StorageEscrowBytes: 10, EvidenceEscrowBytes: 20,
	}
	snapshot := CapacitySnapshot{
		Nodes: []NodeCapacity{
			{Name: "worker-b", RootAvailableBytes: 110, ImageAvailableBytes: 50},
			{Name: "worker-a", RootAvailableBytes: 200, ImageAvailableBytes: 60},
		},
		CorpusAvailableBytes: 220,
	}
	receipt, err := EvaluateCapacity(policy, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Admitted || receipt.Digest == "" || receipt.Snapshot.Nodes[0].Name != "worker-a" {
		t.Fatalf("unexpected admission: %+v", receipt)
	}
	snapshot.Nodes[0].RootAvailableBytes = 109
	rejected, err := EvaluateCapacity(policy, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Admitted || !strings.Contains(rejected.Reason, "root filesystem") {
		t.Fatalf("capacity shortage was not classified: %+v", rejected)
	}
}

func TestPhysicalEscrowIdentityRejectsSparseFile(t *testing.T) {
	contract := "sha256:" + strings.Repeat("a", 64)
	path := filepath.Join(t.TempDir(), ".capacity-escrow-"+strings.Repeat("a", 64))
	if err := os.WriteFile(path+".owner", []byte(contract+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(16 << 20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PhysicalEscrowIdentity(path); err == nil {
		t.Fatal("sparse capacity escrow was accepted as physical allocation")
	}
}

func TestPhysicalEscrowRefusesForeignExactSizeFile(t *testing.T) {
	root := t.TempDir()
	contract := "sha256:" + strings.Repeat("b", 64)
	name := ".capacity-escrow-" + strings.Repeat("b", 64)
	path := filepath.Join(root, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(make([]byte, 1<<20)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePhysicalEscrow(root, name, 1<<20, contract); err == nil ||
		!strings.Contains(err.Error(), "unowned") {
		t.Fatalf("foreign exact-size file was adopted: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign file was mutated: %v", err)
	}
}

func TestPhysicalEscrowResumesOnlyExactContract(t *testing.T) {
	root := t.TempDir()
	contract := "sha256:" + strings.Repeat("c", 64)
	name := ".capacity-escrow-" + strings.Repeat("c", 64)
	path, err := CreatePhysicalEscrow(root, name, 1<<20, contract)
	if err != nil {
		t.Fatal(err)
	}
	first, err := PhysicalEscrowIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := CreatePhysicalEscrow(root, name, 1<<20, contract)
	if err != nil || resumed != path {
		t.Fatalf("exact escrow did not resume: %s, %v", resumed, err)
	}
	second, err := PhysicalEscrowIdentity(path)
	if err != nil || second != first {
		t.Fatalf("resumed escrow identity changed: %q != %q, %v", second, first, err)
	}
	if err := ReleasePhysicalEscrow(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".owner"); !os.IsNotExist(err) {
		t.Fatalf("ownership marker survived exact release: %v", err)
	}
}

func TestLeaseNeverStealsAndBreakRequiresExactIdentity(t *testing.T) {
	ctx := context.Background()
	holder := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	duration := int32(30)
	old := metav1.NewMicroTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	resourceVersion := "7"
	existing := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionLeaseName, Namespace: "test",
			UID: types.UID("lease-uid"), ResourceVersion: resourceVersion,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &other, LeaseDurationSeconds: &duration,
			RenewTime: &old,
		},
	}
	client := fake.NewClientset(existing)
	manager, err := NewLeaseManager(
		client.CoordinationV1(), "test",
		func() time.Time { return old.Time.Add(time.Hour) }, 30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Acquire(ctx, holder); err == nil ||
		!strings.Contains(err.Error(), "explicitly break") {
		t.Fatalf("expired competing lease was stolen: %v", err)
	}
	if err := manager.Break(ctx, existing.UID, "wrong", other, "operator observed stale process"); err == nil {
		t.Fatal("lease with changed resource version was broken")
	}
	if err := manager.Break(ctx, existing.UID, resourceVersion, other, "operator observed stale process"); err != nil {
		t.Fatal(err)
	}
	created, err := manager.Acquire(ctx, holder)
	if err != nil {
		t.Fatal(err)
	}
	if created.Spec.HolderIdentity == nil || *created.Spec.HolderIdentity != holder {
		t.Fatal("new session did not acquire released lease")
	}
}

func TestLeaseReleaseTreatsReplacementAsProofOldLeaseIsGone(t *testing.T) {
	ctx := context.Background()
	holder := "sha256:" + strings.Repeat("d", 64)
	duration := int32(30)
	old := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionLeaseName, Namespace: "test",
			UID: types.UID("old-uid"), ResourceVersion: "7",
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration},
	}
	client := fake.NewClientset(old)
	manager, err := NewLeaseManager(client.CoordinationV1(), "test", time.Now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CoordinationV1().Leases("test").Delete(ctx, sessionLeaseName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	replacementHolder := "sha256:" + strings.Repeat("e", 64)
	replacement := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionLeaseName, Namespace: "test",
			UID: types.UID("replacement-uid"), ResourceVersion: "8",
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &replacementHolder, LeaseDurationSeconds: &duration},
	}
	if _, err := client.CoordinationV1().Leases("test").Create(ctx, replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(ctx, old, holder); err != nil {
		t.Fatalf("old session could not finish after exact Lease replacement: %v", err)
	}
	current, err := client.CoordinationV1().Leases("test").Get(ctx, sessionLeaseName, metav1.GetOptions{})
	if err != nil || current.UID != replacement.UID || current.Spec.HolderIdentity == nil ||
		*current.Spec.HolderIdentity != replacementHolder {
		t.Fatalf("replacement Lease was changed: %#v, %v", current, err)
	}
}

func TestLeaseRenewDistinguishesDefinitiveOwnershipLoss(t *testing.T) {
	ctx := context.Background()
	holder := "sha256:" + strings.Repeat("f", 64)
	duration := int32(30)
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionLeaseName, Namespace: "test",
			UID: types.UID("lease-uid"), ResourceVersion: "7",
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration},
	}
	client := fake.NewClientset(lease)
	manager, err := NewLeaseManager(client.CoordinationV1(), "test", time.Now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	changed := lease.DeepCopy()
	other := "sha256:" + strings.Repeat("e", 64)
	changed.Spec.HolderIdentity = &other
	if _, err := client.CoordinationV1().Leases("test").Update(ctx, changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Renew(ctx, lease, holder); !errors.Is(err, errLeaseOwnershipLost) {
		t.Fatalf("changed owner was not definitive Lease loss: %v", err)
	}
	if err := client.CoordinationV1().Leases("test").Delete(ctx, sessionLeaseName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Renew(ctx, lease, holder); !errors.Is(err, errLeaseOwnershipLost) {
		t.Fatalf("missing Lease was not definitive ownership loss: %v", err)
	}
}

func TestClassificationSeparatesNetworkAndHarnessFailures(t *testing.T) {
	base := TrialResult{
		Phase: "Failed", Reason: "ProtocolDuringViolated", Attribution: "ProtocolAssertion",
		ViolatedAssertions: []string{"progress:Violated"},
		MechanismFamilies:  []string{"NetworkChaos"},
		EvidenceComplete:   true, IncidentBundleSealed: true, LokiExportComplete: true,
	}
	network, err := Classify(base)
	if err != nil {
		t.Fatal(err)
	}
	if network.Class != "NetworkFailureCandidate" || network.Fingerprint == "" {
		t.Fatalf("trusted protocol failure was misclassified: %+v", network)
	}
	base.EvidenceComplete = false
	harness, err := Classify(base)
	if err != nil {
		t.Fatal(err)
	}
	if harness.Class != "HarnessFailed" {
		t.Fatalf("missing evidence was promoted: %+v", harness)
	}
	base.EvidenceComplete = true
	base.Attribution = "Attacknet"
	harness, err = Classify(base)
	if err != nil || harness.Class != "HarnessFailed" {
		t.Fatalf("apparatus failure was promoted: %+v, %v", harness, err)
	}
}

func TestClassificationRejectsContradictoryPassedResults(t *testing.T) {
	base := TrialResult{
		Phase: "Passed", Reason: "AllRecovered", Attribution: "ProtocolAssertion",
		EvidenceComplete: true, IncidentBundleSealed: true, LokiExportComplete: true,
	}
	for name, mutate := range map[string]func(*TrialResult){
		"violated assertion": func(result *TrialResult) {
			result.ViolatedAssertions = []string{"recovery/chain-progress:Violated"}
		},
		"identity divergence": func(result *TrialResult) {
			result.IdentityDivergence = "PodIdentityChanged"
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := base
			mutate(&result)
			classification, err := Classify(result)
			if err != nil {
				t.Fatal(err)
			}
			if classification.Class != "HarnessFailed" ||
				classification.Reason != "ContradictoryTerminalResult" {
				t.Fatalf("contradictory pass was promoted: %+v", classification)
			}
		})
	}
}
