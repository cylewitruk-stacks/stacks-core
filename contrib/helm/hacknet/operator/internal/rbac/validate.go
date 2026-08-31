// Package rbac validates the rendered least-privilege boundary between the
// topology and experiment controllers.
package rbac

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const runComponent = "run-operator"

var (
	readVerbs      = []string{"get", "list", "watch"}
	chaosVerbs     = []string{"create", "delete", "get", "list", "watch"}
	configMapVerbs = []string{"create", "delete", "get", "list", "patch", "watch"}
	topologyRules  = []rbacv1.PolicyRule{
		rule("testing.stacks.org", []string{"stacksnetworks", "burnchainpolicies", "upgradecampaigns"}, readVerbs),
		rule("testing.stacks.org", []string{"upgradecampaigns"}, []string{"patch"}),
		rule("testing.stacks.org", []string{"stacksnetworks/status", "burnchainpolicies/status", "upgradecampaigns/status"}, []string{"get", "patch"}),
		rule("", []string{"configmaps", "services"}, configMapVerbs),
		rule("", []string{"pods"}, readVerbs),
		rule("discovery.k8s.io", []string{"endpointslices"}, readVerbs),
		rule("apps", []string{"statefulsets", "deployments"}, configMapVerbs),
		rule("networking.k8s.io", []string{"networkpolicies"}, configMapVerbs),
	}
	runRules = []rbacv1.PolicyRule{
		rule("testing.stacks.org", []string{"burnchainpolicies", "stacksnetworks"}, readVerbs),
		rule("testing.stacks.org", []string{"burnchainpolicies"}, []string{"patch"}),
		rule("testing.stacks.org", []string{"faultcampaigns", "upgradecampaigns"}, []string{"create", "delete", "get", "list", "patch", "watch"}),
		rule("testing.stacks.org", []string{"attacknetruns"}, []string{"get", "list", "patch", "watch"}),
		rule("testing.stacks.org", []string{"faultcampaigns/status", "upgradecampaigns/status", "attacknetruns/status"}, []string{"get", "patch"}),
		rule("", []string{"pods"}, configMapVerbs),
		rule("", []string{"configmaps"}, configMapVerbs),
		rule("chaos-mesh.org", []string{"dnschaos", "iochaos", "networkchaos", "podchaos", "timechaos"}, chaosVerbs),
	}
)

// Validate decodes rendered Kubernetes resources and verifies both operator
// Roles structurally, independent of YAML presentation style.
func Validate(source io.Reader) error {
	roles, err := decodeRoles(source)
	if err != nil {
		return err
	}
	var topologyRole, runRole *rbacv1.Role
	for index := range roles {
		role := &roles[index]
		if role.Labels["app.kubernetes.io/component"] == runComponent {
			if runRole != nil {
				return fmt.Errorf("rendered chart contains multiple run-operator Roles")
			}
			runRole = role
			continue
		}
		if topologyRole != nil {
			return fmt.Errorf("rendered chart contains multiple topology-operator Roles")
		}
		topologyRole = role
	}
	if topologyRole == nil || runRole == nil {
		return fmt.Errorf("rendered chart must contain one topology Role and one run-operator Role")
	}
	if err := validateTopologyRole(topologyRole); err != nil {
		return fmt.Errorf("topology Role: %w", err)
	}
	if err := validateRunRole(runRole); err != nil {
		return fmt.Errorf("run-operator Role: %w", err)
	}
	return nil
}

func decodeRoles(source io.Reader) ([]rbacv1.Role, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(source, 4096)
	roles := []rbacv1.Role{}
	for {
		object := &unstructured.Unstructured{}
		if err := decoder.Decode(object); err != nil {
			if err == io.EOF {
				return roles, nil
			}
			return nil, fmt.Errorf("decode rendered Kubernetes resources: %w", err)
		}
		if len(object.Object) == 0 || object.GetAPIVersion() != rbacv1.SchemeGroupVersion.String() || object.GetKind() != "Role" {
			continue
		}
		role := rbacv1.Role{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &role); err != nil {
			return nil, fmt.Errorf("decode Role %q: %w", object.GetName(), err)
		}
		roles = append(roles, role)
	}
}

func validateTopologyRole(role *rbacv1.Role) error {
	return requireExactRules(role, topologyRules)
}

func validateRunRole(role *rbacv1.Role) error {
	return requireExactRules(role, runRules)
}

func rule(group string, resources, verbs []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: []string{group}, Resources: resources, Verbs: verbs}
}

func requireExactRules(role *rbacv1.Role, expected []rbacv1.PolicyRule) error {
	actual := normalizedRules(role.Rules)
	wanted := normalizedRules(expected)
	if reflect.DeepEqual(actual, wanted) {
		return nil
	}
	return fmt.Errorf("rules differ from the exact least-privilege contract: got %s; want %s", strings.Join(actual, "; "), strings.Join(wanted, "; "))
}

func normalizedRules(rules []rbacv1.PolicyRule) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, fmt.Sprintf(
			"groups=%s resources=%s verbs=%s names=%s urls=%s",
			strings.Join(sorted(rule.APIGroups), ","),
			strings.Join(sorted(rule.Resources), ","),
			strings.Join(sorted(rule.Verbs), ","),
			strings.Join(sorted(rule.ResourceNames), ","),
			strings.Join(sorted(rule.NonResourceURLs), ","),
		))
	}
	sort.Strings(result)
	return result
}

func sorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
