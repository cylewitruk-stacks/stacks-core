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
    resources: ["stacksnetworks"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["stacksnetworks/status"]
    verbs: ["get", "patch"]
  - apiGroups: ["apps"]
    resources: ["statefulsets"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["configmaps", "services"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: run
  labels: {app.kubernetes.io/component: run-operator}
rules:
  - apiGroups: ["testing.stacks.org"]
    resources: ["stacksnetworks"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["faultcampaigns"]
    verbs: ["get", "list", "watch", "create", "patch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["attacknetruns"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["testing.stacks.org"]
    resources: ["faultcampaigns/status", "attacknetruns/status"]
    verbs: ["get", "patch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "delete"]
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
    verbs:
      - get
      - list
      - watch
  - apiGroups: [testing.stacks.org]
    resources: [stacksnetworks/status]
    verbs: [get, patch]
  - apiGroups:
      - apps
    resources:
      - statefulsets
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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: run
  labels:
    app.kubernetes.io/component: run-operator
rules:
  - {apiGroups: [testing.stacks.org], resources: [stacksnetworks], verbs: [get, list, watch]}
  - {apiGroups: [testing.stacks.org], resources: [faultcampaigns], verbs: [get, list, watch, create, patch]}
  - {apiGroups: [testing.stacks.org], resources: [attacknetruns], verbs: [get, list, watch]}
  - {apiGroups: [testing.stacks.org], resources: [faultcampaigns/status, attacknetruns/status], verbs: [get, patch]}
  - {apiGroups: [""], resources: [configmaps], verbs: [get, list, watch, create, patch, delete]}
  - {apiGroups: [""], resources: [pods], verbs: [get, list, watch, create, delete]}
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
		"  - {apiGroups: [\"\"], resources: [pods], verbs: [get, list, watch, create, delete]}",
		"  - {apiGroups: [\"\"], resources: [pods], verbs: [get, list, watch, create, delete]}\n  - apiGroups: [apps]\n    resources:\n      - statefulsets\n    verbs: [create]",
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
