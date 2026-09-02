package topology

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const telemetryReadyCondition = "TelemetryExporterServiceReady"

// telemetryDependency is one same-namespace exporter Service port.
type telemetryDependency struct {
	name     string
	portName string
	port     int32
}

// validateV1Beta1Telemetry requires enabled exporters to declare a verifiable
// same-namespace Service contract.
func validateV1Beta1Telemetry(network *attacknetv1beta1.StacksNetwork) error {
	for _, telemetry := range effectiveV1Beta1Telemetry(network) {
		if telemetry.Enabled == nil || !*telemetry.Enabled {
			continue
		}
		if telemetry.ExporterEndpoint == "" {
			return fmt.Errorf("enabled telemetry requires exporterEndpoint")
		}
		if telemetry.ExporterServiceRef == nil {
			return fmt.Errorf("enabled telemetry requires exporterServiceRef so readiness can be verified")
		}
		if err := validateTelemetryEndpoint(network.Namespace, telemetry); err != nil {
			return err
		}
	}
	return nil
}

// validateTelemetryEndpoint binds a configured URL to its declared Service.
func validateTelemetryEndpoint(namespace string, telemetry attacknetv1beta1.TelemetrySpec) error {
	reference := telemetry.ExporterServiceRef
	if len(utilvalidation.IsDNS1123Label(reference.Name)) != 0 || len(utilvalidation.IsDNS1123Label(reference.PortName)) != 0 || len(reference.PortName) > 15 || reference.Port < 1 || reference.Port > 65535 {
		return fmt.Errorf("telemetry exporterServiceRef requires DNS-label name and portName fields and a port between 1 and 65535")
	}
	parsed, err := url.Parse(telemetry.ExporterEndpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("telemetry exporterEndpoint %q must be an absolute HTTP URL", telemetry.ExporterEndpoint)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("telemetry exporterEndpoint %q must use http or https", telemetry.ExporterEndpoint)
	}
	wantPort := strconv.Itoa(int(reference.Port))
	if parsed.Port() != wantPort {
		return fmt.Errorf("telemetry exporterEndpoint port %q does not match exporterServiceRef port %s", parsed.Port(), wantPort)
	}
	allowedHosts := map[string]struct{}{
		reference.Name:                                          {},
		reference.Name + "." + namespace:                        {},
		reference.Name + "." + namespace + ".svc":               {},
		reference.Name + "." + namespace + ".svc.cluster.local": {},
	}
	if _, ok := allowedHosts[strings.ToLower(parsed.Hostname())]; !ok {
		return fmt.Errorf("telemetry exporterEndpoint host %q does not match same-namespace Service %q", parsed.Hostname(), reference.Name)
	}
	return nil
}

// effectiveV1Beta1Telemetry resolves network and actor workload overrides using
// the same precedence as the workload renderer.
func effectiveV1Beta1Telemetry(network *attacknetv1beta1.StacksNetwork) []attacknetv1beta1.TelemetrySpec {
	base := mergeV1Beta1Telemetry(attacknetv1beta1.TelemetrySpec{}, network.Spec.Telemetry)
	result := make([]attacknetv1beta1.TelemetrySpec, 0, len(network.Spec.Burnchain.Nodes)+len(network.Spec.Nodes)+len(network.Spec.RawActors))
	appendWorkload := func(workload *attacknetv1beta1.WorkloadPolicy) {
		var override *attacknetv1beta1.TelemetrySpec
		if workload != nil {
			override = workload.Telemetry
		}
		result = append(result, mergeV1Beta1Telemetry(base, override))
	}
	for index := range network.Spec.Burnchain.Nodes {
		appendWorkload(network.Spec.Burnchain.Nodes[index].Workload)
	}
	for index := range network.Spec.Nodes {
		appendWorkload(network.Spec.Nodes[index].Workload)
	}
	for setIndex := range network.Spec.SignerSets {
		for memberIndex := range network.Spec.SignerSets[setIndex].Members {
			member := &network.Spec.SignerSets[setIndex].Members[memberIndex]
			appendWorkload(member.NodeWorkload)
			appendWorkload(member.SignerWorkload)
		}
	}
	if network.Spec.Enrollment != nil {
		appendWorkload(network.Spec.Enrollment.Workload)
	}
	for index := range network.Spec.RawActors {
		appendWorkload(network.Spec.RawActors[index].Workload)
	}
	return result
}

// mergeV1Beta1Telemetry applies non-zero telemetry override fields.
func mergeV1Beta1Telemetry(target attacknetv1beta1.TelemetrySpec, source *attacknetv1beta1.TelemetrySpec) attacknetv1beta1.TelemetrySpec {
	if source == nil {
		return target
	}
	if source.Enabled != nil {
		target.Enabled = source.Enabled
	}
	if source.Image != "" {
		target.Image = source.Image
	}
	if source.ImagePullPolicy != "" {
		target.ImagePullPolicy = source.ImagePullPolicy
	}
	if source.Resources != nil {
		target.Resources = source.Resources
	}
	if source.MetricsPort != 0 {
		target.MetricsPort = source.MetricsPort
	}
	if source.ExporterEndpoint != "" {
		target.ExporterEndpoint = source.ExporterEndpoint
	}
	if source.ExporterServiceRef != nil {
		copy := *source.ExporterServiceRef
		target.ExporterServiceRef = &copy
	}
	if source.TokenSecretRef != nil {
		copy := *source.TokenSecretRef
		target.TokenSecretRef = &copy
	}
	return target
}

// v1Beta1TelemetryDependencies returns sorted unique exporter dependencies.
func v1Beta1TelemetryDependencies(network *attacknetv1beta1.StacksNetwork) []telemetryDependency {
	seen := map[telemetryDependency]struct{}{}
	for _, telemetry := range effectiveV1Beta1Telemetry(network) {
		if telemetry.Enabled == nil || !*telemetry.Enabled || telemetry.ExporterServiceRef == nil {
			continue
		}
		seen[telemetryDependency{name: telemetry.ExporterServiceRef.Name, portName: telemetry.ExporterServiceRef.PortName, port: telemetry.ExporterServiceRef.Port}] = struct{}{}
	}
	result := make([]telemetryDependency, 0, len(seen))
	for dependency := range seen {
		result = append(result, dependency)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].name == result[right].name {
			if result[left].portName == result[right].portName {
				return result[left].port < result[right].port
			}
			return result[left].portName < result[right].portName
		}
		return result[left].name < result[right].name
	})
	return result
}

// observeV1Beta1Telemetry verifies Service and ready EndpointSlice state without
// claiming ownership of the externally managed observability stack.
func observeV1Beta1Telemetry(ctx context.Context, reader client.Reader, network *attacknetv1beta1.StacksNetwork) (bool, string, string, error) {
	dependencies := v1Beta1TelemetryDependencies(network)
	if len(dependencies) == 0 {
		return true, "TelemetryDisabled", "actor telemetry is disabled", nil
	}
	for _, dependency := range dependencies {
		service := &corev1.Service{}
		key := types.NamespacedName{Namespace: network.Namespace, Name: dependency.name}
		if err := reader.Get(ctx, key, service); err != nil {
			if client.IgnoreNotFound(err) == nil {
				return false, "TelemetryExporterServiceNotFound", fmt.Sprintf("telemetry exporter Service %s does not exist", dependency.name), nil
			}
			return false, "", "", fmt.Errorf("read telemetry exporter Service %s: %w", dependency.name, err)
		}
		portFound := false
		for _, port := range service.Spec.Ports {
			if port.Name == dependency.portName && port.Port == dependency.port {
				portFound = true
				break
			}
		}
		if !portFound {
			return false, "TelemetryExporterPortNotFound", fmt.Sprintf("telemetry exporter Service %s does not expose named port %s at %d", dependency.name, dependency.portName, dependency.port), nil
		}
		slices := &discoveryv1.EndpointSliceList{}
		if err := reader.List(ctx, slices, client.InNamespace(network.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: dependency.name}); err != nil {
			return false, "", "", fmt.Errorf("list telemetry exporter EndpointSlices for %s: %w", dependency.name, err)
		}
		if !endpointSlicesReady(slices.Items, dependency.portName) {
			return false, "TelemetryExporterUnavailable", fmt.Sprintf("telemetry exporter Service %s has no ready endpoint for port %d", dependency.name, dependency.port), nil
		}
	}
	return true, "TelemetryExporterReady", fmt.Sprintf("%d telemetry exporter service binding(s) are ready", len(dependencies)), nil
}

// endpointSlicesReady reports whether a named Service port has a ready endpoint.
func endpointSlicesReady(slices []discoveryv1.EndpointSlice, portName string) bool {
	for _, slice := range slices {
		portPresent := false
		for _, port := range slice.Ports {
			if port.Name != nil && *port.Name == portName {
				portPresent = true
				break
			}
		}
		if !portPresent {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
				return true
			}
		}
	}
	return false
}

// setV1Beta1TelemetryCondition records telemetry readiness and withdraws overall
// readiness when a declared dependency is unavailable.
func setV1Beta1TelemetryCondition(status *attacknetv1beta1.StacksNetworkStatus, generation int64, ready bool, reason, message string) {
	conditionStatus := metav1.ConditionFalse
	if ready {
		conditionStatus = metav1.ConditionTrue
	}
	condition := metav1.Condition{Type: telemetryReadyCondition, Status: conditionStatus, ObservedGeneration: generation, Reason: reason, Message: message}
	meta.SetStatusCondition(&status.Conditions, condition)
	if !ready {
		status.Phase = "Pending"
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: generation, Reason: reason, Message: message})
	}
}
