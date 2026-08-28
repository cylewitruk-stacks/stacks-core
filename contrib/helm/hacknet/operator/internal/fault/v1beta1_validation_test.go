package fault

import (
	"strings"
	"testing"
	"time"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

func TestValidateV1Beta1StructureRejectsInvalidFaultContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*attacknetv1beta1.FaultCampaign)
		want   string
	}{
		{
			name: "type action mismatch",
			mutate: func(campaign *attacknetv1beta1.FaultCampaign) {
				campaign.Spec.Stages[0].Faults[0].Fault.Type = "dns"
			},
			want: "unsupported dns action",
		},
		{
			name: "fixed mode missing value",
			mutate: func(campaign *attacknetv1beta1.FaultCampaign) {
				campaign.Spec.Stages[0].Faults[0].Fault.Mode = "fixed"
			},
			want: "value is required",
		},
		{
			name: "percent exceeds one hundred",
			mutate: func(campaign *attacknetv1beta1.FaultCampaign) {
				campaign.Spec.Stages[0].Faults[0].Fault.Mode = "fixed-percent"
				value := intstr.FromInt(101)
				campaign.Spec.Stages[0].Faults[0].Fault.Value = &value
			},
			want: "must not exceed 100",
		},
		{
			name: "missing target",
			mutate: func(campaign *attacknetv1beta1.FaultCampaign) {
				campaign.Spec.Stages[0].Faults[0].Target.Actors = nil
			},
			want: "target requires actors or roles",
		},
		{
			name: "missing mechanism parameter",
			mutate: func(campaign *attacknetv1beta1.FaultCampaign) {
				action := &campaign.Spec.Stages[0].Faults[0]
				action.Fault.Type, action.Fault.Action = "dns", "error"
				action.Fault.Parameters = apixv1.JSON{}
			},
			want: "requires parameters.patterns",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			campaign := betaCampaignFixture()
			test.mutate(campaign)
			err := ValidateV1Beta1Structure(campaign)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestValidateV1Beta1BurnchainReorgContract(t *testing.T) {
	campaign := betaCampaignFixture()
	campaign.Spec.Stages[0].Faults[0] = attacknetv1beta1.FaultActionSpec{
		ID: "replace-tip", Target: attacknetv1beta1.FaultTarget{Actors: []string{"bitcoin-1"}, Mode: "one"},
		Fault: attacknetv1beta1.FaultSpec{
			Type: "burnchain-reorg", Mode: "one", Duration: metav1.Duration{Duration: 30 * time.Second},
			BurnchainReorg: &attacknetv1beta1.BurnchainReorgFaultSpec{Depth: 2, ReplacementBlocks: 3},
		},
	}
	campaign.Spec.Safety.AllowBurnchain = true
	campaign.Spec.Safety.MaxBurnchainReorgDepth = 2
	campaign.Spec.Safety.MaxBurnchainReplacementBlocks = 3
	if err := ValidateV1Beta1Structure(campaign); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*attacknetv1beta1.FaultCampaign)
		want   string
	}{
		{"replacement not longer", func(value *attacknetv1beta1.FaultCampaign) {
			value.Spec.Stages[0].Faults[0].Fault.BurnchainReorg.ReplacementBlocks = 2
		}, "must exceed depth"},
		{"raw RPC parameters", func(value *attacknetv1beta1.FaultCampaign) {
			value.Spec.Stages[0].Faults[0].Fault.Parameters = apixv1.JSON{Raw: []byte(`{"method":"invalidateblock"}`)}
		}, "does not accept"},
		{"depth budget", func(value *attacknetv1beta1.FaultCampaign) { value.Spec.Safety.MaxBurnchainReorgDepth = 1 }, "exceeds safety maximum"},
		{"replacement schedule exceeds duration", func(value *attacknetv1beta1.FaultCampaign) {
			value.Spec.Stages[0].Faults[0].Fault.BurnchainReorg.ReplacementInterval = metav1.Duration{Duration: 20 * time.Second}
		}, "schedule exceeds fault.duration"},
		{"role selector", func(value *attacknetv1beta1.FaultCampaign) {
			value.Spec.Stages[0].Faults[0].Target = attacknetv1beta1.FaultTarget{Roles: []string{"burnchain"}}
		}, "exactly one Bitcoin actor"},
		{"target mode", func(value *attacknetv1beta1.FaultCampaign) {
			value.Spec.Stages[0].Faults[0].Target.Mode = "all"
		}, "target mode one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := campaign.DeepCopy()
			test.mutate(copy)
			err := ValidateV1Beta1Structure(copy)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %q", err, test.want)
			}
		})
	}
}
