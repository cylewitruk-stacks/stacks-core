package fault

import (
	"strings"
	"testing"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
