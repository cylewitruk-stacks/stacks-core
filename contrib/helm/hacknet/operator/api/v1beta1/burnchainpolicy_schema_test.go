package v1beta1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestBurnchainPolicyCRDMatchesTypedAPIAndBoundsDestinations(t *testing.T) {
	path := filepath.Join("..", "..", "..", "crds", "testing.stacks.org_burnchainpolicies.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := yaml.ToJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	crd := apixv1.CustomResourceDefinition{}
	if err := json.Unmarshal(jsonData, &crd); err != nil {
		t.Fatal(err)
	}
	if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != Version || crd.Spec.Versions[0].Schema == nil {
		t.Fatalf("BurnchainPolicy must expose exactly one %s schema", Version)
	}
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	compareBurnchainFields(t, reflect.TypeOf(BurnchainPolicySpec{}), root.Properties["spec"], "spec")
	compareBurnchainFields(t, reflect.TypeOf(BurnchainPolicyStatus{}), root.Properties["status"], "status")
	destinations := root.Properties["spec"].Properties["destinations"]
	if destinations.MinItems == nil || *destinations.MinItems != 1 || destinations.MaxItems == nil || *destinations.MaxItems != 64 {
		t.Fatalf("destinations are not bounded: %#v", destinations)
	}
	selection := root.Properties["spec"].Properties["destinationSelection"]
	if !reflect.DeepEqual(selection.Enum, []apixv1.JSON{{Raw: []byte(`"round-robin"`)}, {Raw: []byte(`"fixed"`)}}) {
		t.Fatalf("destination selection is not a closed enum: %#v", selection.Enum)
	}
	validations := root.Properties["spec"].Properties["rpc"].XValidations
	if len(validations) != 1 || !strings.Contains(validations[0].Rule, "usernameSecretRef") {
		t.Fatal("paired RPC Secret references are not enforced by the CRD")
	}
}

func compareBurnchainFields(t *testing.T, typ reflect.Type, schema apixv1.JSONSchemaProps, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || typ.PkgPath() != reflect.TypeOf(BurnchainPolicy{}).PkgPath() {
		return
	}
	for index := range typ.NumField() {
		field := typ.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		property, ok := schema.Properties[name]
		if !ok {
			t.Errorf("%s.%s exists in %s but not in the CRD", path, name, typ.Name())
			continue
		}
		nested := field.Type
		for nested.Kind() == reflect.Pointer {
			nested = nested.Elem()
		}
		if nested.Kind() == reflect.Slice {
			nested = nested.Elem()
			for nested.Kind() == reflect.Pointer {
				nested = nested.Elem()
			}
			if property.Items == nil || property.Items.Schema == nil {
				continue
			}
			property = *property.Items.Schema
		}
		compareBurnchainFields(t, nested, property, path+"."+name)
	}
	for name := range schema.Properties {
		found := false
		for index := range typ.NumField() {
			if strings.Split(typ.Field(index).Tag.Get("json"), ",")[0] == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s.%s exists in the CRD but not in %s", path, name, typ.Name())
		}
	}
}
