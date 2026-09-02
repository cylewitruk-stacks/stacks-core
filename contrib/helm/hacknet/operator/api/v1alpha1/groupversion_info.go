// Package v1alpha1 contains the typed Hacknet and Attacknet Kubernetes APIs.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Group is the Kubernetes API group used by the test-network resources.
	Group = "testing.stacks.org"
	// Version is the currently served API version.
	Version = "v1alpha1"
)

var (
	// GroupVersion identifies the Hacknet API group and version.
	GroupVersion = schema.GroupVersion{Group: Group, Version: Version}
	// SchemeBuilder registers all Hacknet API objects.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme adds all Hacknet API objects to a runtime scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&StacksNetwork{}, &StacksNetworkList{},
		&FaultCampaign{}, &FaultCampaignList{},
		&AttacknetRun{}, &AttacknetRunList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
