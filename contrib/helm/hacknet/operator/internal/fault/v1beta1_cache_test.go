package fault

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestCompilationCacheKeysImmutableInputsAndReturnsDefensiveCopies(t *testing.T) {
	compileCalls := 0
	cache, err := newCompilationCache(2, func(campaign *attacknetv1beta1.FaultCampaign, manifest Manifest) (CompiledCampaign, error) {
		compileCalls++
		return CompileV1Beta1(campaign, manifest)
	})
	if err != nil {
		t.Fatal(err)
	}
	campaign := betaCampaignFixture()
	campaign.UID = types.UID("campaign-uid")
	manifest := betaManifestFixture()
	first, err := cache.Compile(campaign, manifest)
	if err != nil {
		t.Fatal(err)
	}
	first.Stages[0].Actions[0].Resource.SetName("mutated-by-caller")
	second, err := cache.Compile(campaign.DeepCopy(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if compileCalls != 1 {
		t.Fatalf("compiler calls = %d, want one cache miss", compileCalls)
	}
	if second.Stages[0].Actions[0].Resource.GetName() == "mutated-by-caller" {
		t.Fatal("caller mutation escaped into cached compilation")
	}

	changed := campaign.DeepCopy()
	changed.Generation++
	if _, err := cache.Compile(changed, manifest); err != nil {
		t.Fatal(err)
	}
	if compileCalls != 2 {
		t.Fatalf("compiler calls = %d, want generation cache miss", compileCalls)
	}
	cache.Forget(campaign.UID)
	if _, err := cache.Compile(campaign, manifest); err != nil {
		t.Fatal(err)
	}
	if compileCalls != 3 {
		t.Fatalf("compiler calls = %d, want miss after terminal eviction", compileCalls)
	}
}

func TestCompilationCacheEvictsLeastRecentlyUsedEntry(t *testing.T) {
	compileCalls := 0
	cache, err := newCompilationCache(1, func(campaign *attacknetv1beta1.FaultCampaign, manifest Manifest) (CompiledCampaign, error) {
		compileCalls++
		return CompileV1Beta1(campaign, manifest)
	})
	if err != nil {
		t.Fatal(err)
	}
	first := betaCampaignFixture()
	first.UID = "first"
	second := betaCampaignFixture()
	second.Name, second.UID = "second", "second"
	for _, campaign := range []*attacknetv1beta1.FaultCampaign{first, second, first} {
		if _, err := cache.Compile(campaign, betaManifestFixture()); err != nil {
			t.Fatal(err)
		}
	}
	if compileCalls != 3 {
		t.Fatalf("compiler calls = %d, want bounded LRU eviction", compileCalls)
	}
}
