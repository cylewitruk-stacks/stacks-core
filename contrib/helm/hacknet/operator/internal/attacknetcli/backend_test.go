package attacknetcli

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	discoveryfake "k8s.io/client-go/discovery/fake"
	kubetesting "k8s.io/client-go/testing"
)

func TestDiagnoseUsesClosedKindCatalog(t *testing.T) {
	resources := make([]metav1.APIResource, 0, len(resourceKinds))
	for _, kind := range resourceKinds {
		resources = append(resources, metav1.APIResource{Name: kind.Plural, Kind: kind.Name, Namespaced: true})
	}
	discovery := &discoveryfake.FakeDiscovery{Fake: &kubetesting.Fake{Resources: []*metav1.APIResourceList{{
		GroupVersion: resourceKinds[0].GVK.GroupVersion().String(), APIResources: resources,
	}}}}
	discovery.FakedServerVersion = &version.Info{GitVersion: "v1.36.2"}
	backend := &KubernetesBackend{discovery: discovery}
	report, err := backend.Diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || len(report.APIs) != len(resourceKinds) || report.ServerVersion != "v1.36.2" {
		t.Fatalf("unexpected report: %#v", report)
	}

	discovery.Resources[0].APIResources = discovery.Resources[0].APIResources[:len(resources)-1]
	report, err = backend.Diagnose(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready || report.APIs[len(report.APIs)-1].Available {
		t.Fatalf("missing API was accepted: %#v", report)
	}
}
