package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Group is the Kubernetes API group used by Attacknet resources.
	Group = "testing.stacks.org"
	// Version is the v1beta1 API version.
	Version = "v1beta1"
)

var (
	// GroupVersion identifies the Attacknet API group and version.
	GroupVersion = schema.GroupVersion{Group: Group, Version: Version}
	// SchemeBuilder registers all v1beta1 API objects.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme adds all v1beta1 objects to a runtime scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&StacksNetwork{}, &StacksNetworkList{},
		&BurnchainPolicy{}, &BurnchainPolicyList{},
		&FaultCampaign{}, &FaultCampaignList{},
		&AttacknetRun{}, &AttacknetRunList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
