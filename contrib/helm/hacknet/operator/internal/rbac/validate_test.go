package rbac

import (
	"strings"
	"testing"
)

const flowStyleRoles = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: topology}
rules:
  - apiGroups: ["testing.stacks.org"]
    resources: ["stacksnetworks", "burnchainpolicies", "upgradecampaigns"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["upgradecampaigns"]
    verbs: ["patch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["stacksnetworks/status", "burnchainpolicies/status", "upgradecampaigns/status"]
    verbs: ["get", "patch"]
  - apiGroups: ["apps"]
    resources: ["statefulsets", "deployments"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["configmaps", "services"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: run
  labels: {app.kubernetes.io/component: run-operator}
rules:
  - apiGroups: ["testing.stacks.org"]
    resources: ["stacksnetworks", "burnchainpolicies"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["burnchainpolicies"]
    verbs: ["patch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["faultcampaigns", "upgradecampaigns"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["attacknetruns"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["faultcampaigns/status", "upgradecampaigns/status", "attacknetruns/status"]
    verbs: ["get", "patch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: ["chaos-mesh.org"]
    resources: ["podchaos", "networkchaos", "dnschaos", "iochaos", "timechaos"]
    verbs: ["get", "list", "watch", "create", "delete"]
`

const blockStyleRoles = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: topology
rules:
  - apiGroups:
      - testing.stacks.org
    resources:
      - stacksnetworks
      - burnchainpolicies
      - upgradecampaigns
    verbs:
      - get
      - list
      - watch
  - apiGroups: [testing.stacks.org]
    resources: [upgradecampaigns]
    verbs: [patch]
  - apiGroups: [testing.stacks.org]
    resources: [stacksnetworks/status, burnchainpolicies/status, upgradecampaigns/status]
    verbs: [get, patch]
  - apiGroups:
      - apps
    resources:
      - statefulsets
      - deployments
    verbs:
      - get
      - list
      - watch
      - create
      - patch
      - delete
  - apiGroups:
      - ""
    resources:
      - configmaps
      - services
    verbs:
      - get
      - list
      - watch
      - create
      - patch
      - delete
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, watch]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [get, list, watch, create, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: run
  labels:
    app.kubernetes.io/component: run-operator
rules:
  - {apiGroups: [testing.stacks.org], resources: [stacksnetworks, burnchainpolicies], verbs: [get, list, watch]}
  - {apiGroups: [testing.stacks.org], resources: [burnchainpolicies], verbs: [patch]}
  - {apiGroups: [testing.stacks.org], resources: [faultcampaigns, upgradecampaigns], verbs: [get, list, watch, create, patch, delete]}
  - {apiGroups: [testing.stacks.org], resources: [attacknetruns], verbs: [get, list, watch, patch]}
  - {apiGroups: [testing.stacks.org], resources: [faultcampaigns/status, upgradecampaigns/status, attacknetruns/status], verbs: [get, patch]}
  - {apiGroups: [""], resources: [configmaps], verbs: [get, list, watch, create, patch, delete]}
  - {apiGroups: [""], resources: [pods], verbs: [get, list, watch, create, patch, delete]}
  - {apiGroups: [chaos-mesh.org], resources: [podchaos, networkchaos, dnschaos, iochaos, timechaos], verbs: [get, list, watch, create, delete]}
`

func TestValidateAcceptsEquivalentYAMLStyles(t *testing.T) {
	for name, source := range map[string]string{"flow": flowStyleRoles, "block": blockStyleRoles} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(strings.NewReader(source)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateRejectsRunOperatorTopologyWritesInBlockStyle(t *testing.T) {
	forbidden := strings.Replace(blockStyleRoles,
		"  - {apiGroups: [\"\"], resources: [pods], verbs: [get, list, watch, create, patch, delete]}",
		"  - {apiGroups: [\"\"], resources: [pods], verbs: [get, list, watch, create, patch, delete]}\n  - apiGroups: [apps]\n    resources:\n      - statefulsets\n    verbs: [create]",
		1,
	)
	if err := Validate(strings.NewReader(forbidden)); err == nil || !strings.Contains(err.Error(), "exact least-privilege contract") {
		t.Fatalf("block-style forbidden resource escaped validation: %v", err)
	}
}

func TestValidateRejectsUpdateRegardlessOfRuleFormatting(t *testing.T) {
	forbidden := strings.Replace(flowStyleRoles,
		`  - apiGroups: ["chaos-mesh.org"]`,
		"  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"update\"]\n  - apiGroups: [\"chaos-mesh.org\"]",
		1,
	)
	if err := Validate(strings.NewReader(forbidden)); err == nil || !strings.Contains(err.Error(), "exact least-privilege contract") {
		t.Fatalf("forbidden update escaped validation: %v", err)
	}
}

func TestValidateRejectsAnyUnexpectedPrivilege(t *testing.T) {
	forbidden := strings.Replace(flowStyleRoles,
		`  - apiGroups: ["chaos-mesh.org"]`,
		"  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"get\"]\n  - apiGroups: [\"chaos-mesh.org\"]",
		1,
	)
	if err := Validate(strings.NewReader(forbidden)); err == nil {
		t.Fatal("unexpected read-only privilege escaped the exact contract")
	}
}

func TestValidateRejectsWildcardPrivileges(t *testing.T) {
	forbidden := strings.Replace(flowStyleRoles,
		`  - apiGroups: ["chaos-mesh.org"]`,
		"  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n  - apiGroups: [\"chaos-mesh.org\"]",
		1,
	)
	if err := Validate(strings.NewReader(forbidden)); err == nil {
		t.Fatal("wildcard privilege escaped structural validation")
	}
}
