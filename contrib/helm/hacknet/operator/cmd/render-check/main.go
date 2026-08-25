// Command render-check validates an offline StacksNetwork through the production renderer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/topology"
)

func main() {
	input := flag.String("input", "", "Path to a rendered StacksNetwork JSON document.")
	expected := flag.Int("expected-actors", 0, "Expected actor, Service, and StatefulSet count.")
	output := flag.String("output", "", "Optional path for the rendered resource set; use - for standard output.")
	flag.Parse()
	if *input == "" || *expected < 1 {
		fatal("--input and a positive --expected-actors are required")
	}
	contents, err := os.ReadFile(*input)
	if err != nil {
		fatal(err.Error())
	}
	network := &attacknetv1alpha1.StacksNetwork{}
	if err := json.Unmarshal(contents, network); err != nil {
		fatal(err.Error())
	}
	if network.UID == "" {
		network.UID = types.UID("offline-render-check")
	}
	if network.Generation == 0 {
		network.Generation = 1
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, attacknetv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			fatal(err.Error())
		}
	}
	resources, err := topology.Render(network, scheme)
	if err != nil {
		fatal(err.Error())
	}
	if len(network.Spec.Actors) != *expected || len(resources.Services) != *expected || len(resources.StatefulSets) != *expected {
		fatal(fmt.Sprintf("expected %d actors/services/statefulsets, got %d/%d/%d", *expected, len(network.Spec.Actors), len(resources.Services), len(resources.StatefulSets)))
	}
	if *output != "" {
		encoded, err := json.MarshalIndent(resources, "", "  ")
		if err != nil {
			fatal(err.Error())
		}
		encoded = append(encoded, '\n')
		if *output == "-" {
			if _, err := os.Stdout.Write(encoded); err != nil {
				fatal(err.Error())
			}
			return
		}
		if err := os.WriteFile(*output, encoded, 0o644); err != nil {
			fatal(err.Error())
		}
	}
	fmt.Printf("Offline Go operator validation passed for %d workloads\n", *expected)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
