package topology

import (
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

var exactSHA256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validateNetwork(network *attacknetv1alpha1.StacksNetwork) error {
	if network.Name == "" || network.Namespace == "" || network.UID == "" {
		return fmt.Errorf("metadata.name, metadata.namespace, and metadata.uid are required")
	}
	if len(network.Spec.Actors) < 1 || len(network.Spec.Actors) > 100 {
		return fmt.Errorf("spec.actors must contain between 1 and 100 actors")
	}
	actors := map[string]*attacknetv1alpha1.ActorSpec{}
	validRoles := map[string]bool{"burnchain": true, "miner": true, "signer": true, "companion": true, "follower": true, "adversary": true, "infrastructure": true, "observer": true}
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		if actor.Name == "" || len(actor.Name) > 40 || len(validation.IsDNS1123Label(actor.Name)) > 0 {
			return fmt.Errorf("invalid actor name %q", actor.Name)
		}
		if _, exists := actors[actor.Name]; exists {
			return fmt.Errorf("duplicate actor name %q", actor.Name)
		}
		actors[actor.Name] = actor
		if !validRoles[actor.Role] {
			return fmt.Errorf("actor %q has invalid role %q", actor.Name, actor.Role)
		}
		if actorImage(network, actor) == "" {
			return fmt.Errorf("actor %q has no image and no applicable default image", actor.Name)
		}
		if actor.RuntimeExposure != "" && actor.RuntimeExposure != "ready" && actor.RuntimeExposure != "reachable" {
			return fmt.Errorf("actor %q has invalid runtimeExposure", actor.Name)
		}
		sources := 0
		if actor.Config != nil {
			if actor.Config.Inline != "" {
				sources++
			}
			if actor.Config.Files != nil {
				if len(actor.Config.Files) == 0 {
					return fmt.Errorf("actor %q config files must not be empty", actor.Name)
				}
				sources++
			}
			if actor.Config.ConfigMapRef != nil {
				sources++
			}
			if actor.Config.SecretRef != nil {
				sources++
			}
			for key := range actor.Config.Files {
				if problems := validation.IsConfigMapKey(key); len(problems) > 0 {
					return fmt.Errorf("actor %q config key %q is invalid: %s", actor.Name, key, strings.Join(problems, "; "))
				}
			}
		}
		if sources > 1 {
			return fmt.Errorf("actor %q config must use exactly one inline, files, ConfigMap, or Secret source", actor.Name)
		}
		if (actor.Role == "miner" || actor.Role == "signer" || actor.Role == "companion" || actor.Role == "follower") && sources != 1 {
			return fmt.Errorf("Stacks actor %q requires exactly one config source", actor.Name)
		}
		if problems := validation.IsConfigMapKey(configKey(actor)); len(problems) > 0 {
			return fmt.Errorf("actor %q config key %q is invalid: %s", actor.Name, configKey(actor), strings.Join(problems, "; "))
		}
		if actor.RuntimePolicy != nil {
			name := actor.RuntimePolicy.ConfigMapRef.Name
			if len(name) > 63 || len(validation.IsDNS1123Label(name)) > 0 {
				return fmt.Errorf("actor %q has invalid runtime policy ConfigMap name", actor.Name)
			}
		}
		if actor.AdversarialPolicyDigest != "" && !exactSHA256Pattern.MatchString(actor.AdversarialPolicyDigest) {
			return fmt.Errorf("actor %q has malformed adversarial policy digest", actor.Name)
		}
		switch actor.AdversarialEgressProfile {
		case "":
			if actor.AdversarialPolicyDigest != "" {
				return fmt.Errorf("actor %q has an adversarial policy without an egress profile", actor.Name)
			}
		case "restricted", "unrestricted":
			if actor.AdversarialPolicyDigest == "" {
				return fmt.Errorf("actor %q has an adversarial egress profile without a policy digest", actor.Name)
			}
		default:
			return fmt.Errorf("actor %q has unsupported adversarial egress profile %q", actor.Name, actor.AdversarialEgressProfile)
		}
		ports := map[string]bool{}
		containerPorts := map[string]bool{}
		servicePorts := map[string]bool{}
		for _, port := range effectivePorts(actor) {
			if port.Name == "" || len(port.Name) > 15 || len(validation.IsDNS1123Label(port.Name)) > 0 || port.ContainerPort < 1 || port.ServicePort < 1 {
				return fmt.Errorf("actor %q has an invalid port", actor.Name)
			}
			if ports[port.Name] {
				return fmt.Errorf("actor %q declares duplicate port %q", actor.Name, port.Name)
			}
			containerKey := fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol)
			if containerPorts[containerKey] {
				return fmt.Errorf("actor %q declares duplicate container port %s", actor.Name, containerKey)
			}
			serviceKey := fmt.Sprintf("%d/%s", port.ServicePort, port.Protocol)
			if servicePorts[serviceKey] {
				return fmt.Errorf("actor %q declares duplicate service port %s", actor.Name, serviceKey)
			}
			ports[port.Name] = true
			containerPorts[containerKey] = true
			servicePorts[serviceKey] = true
		}
		if boolValue(probeSettings(network, actor).Enabled, false) {
			if ports["probe"] {
				return fmt.Errorf("actor %q reserves port name probe for the trusted probe sidecar", actor.Name)
			}
			if servicePorts[fmt.Sprintf("%d/%s", 18080, corev1.ProtocolTCP)] {
				return fmt.Errorf("actor %q reserves TCP service port 18080 for the trusted probe sidecar", actor.Name)
			}
		}
		if boolValue(telemetrySettings(network, actor).Enabled, false) && telemetrySettings(network, actor).ExporterEndpoint == "" {
			return fmt.Errorf("actor %q enables telemetry without exporterEndpoint", actor.Name)
		}
		if boolValue(probeSettings(network, actor).Enabled, false) && probeSettings(network, actor).Image == "" {
			return fmt.Errorf("actor %q enables the trusted probe without an image", actor.Name)
		}
	}
	for index := range network.Spec.Actors {
		actor := &network.Spec.Actors[index]
		for _, dependency := range actor.Dependencies {
			if dependency.Port < 1 || dependency.Port > 65535 {
				return fmt.Errorf("actor %q dependency has invalid port %d", actor.Name, dependency.Port)
			}
			if (dependency.Actor == "") == (dependency.Service == "") {
				return fmt.Errorf("actor %q dependency requires exactly one actor or service", actor.Name)
			}
			if dependency.Service != "" {
				if problems := validation.IsDNS1123Subdomain(dependency.Service); len(problems) > 0 {
					return fmt.Errorf("actor %q dependency has invalid Service %q: %s", actor.Name, dependency.Service, strings.Join(problems, "; "))
				}
				continue
			}
			target, exists := actors[dependency.Actor]
			if !exists {
				return fmt.Errorf("actor %q depends on unknown actor %q", actor.Name, dependency.Actor)
			}
			if target == actor {
				return fmt.Errorf("actor %q cannot depend on itself", actor.Name)
			}
			found := false
			for _, port := range effectivePorts(target) {
				if port.ServicePort == dependency.Port {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("actor %q dependency %q uses port %d, which the target does not expose", actor.Name, dependency.Actor, dependency.Port)
			}
		}
	}
	return nil
}
