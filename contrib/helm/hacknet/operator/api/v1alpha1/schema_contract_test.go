package v1alpha1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const apiPackage = "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"

// TestGoTypesMatchAuthoredCRDSchemas prevents the typed API and the
// hand-authored validation schemas from accepting different field sets.
func TestGoTypesMatchAuthoredCRDSchemas(t *testing.T) {
	tests := []struct {
		file   string
		spec   any
		status any
	}{
		{"testing.stacks.org_stacksnetworks.yaml", StacksNetworkSpec{}, StacksNetworkStatus{}},
		{"testing.stacks.org_faultcampaigns.yaml", FaultCampaignSpec{}, FaultCampaignStatus{}},
		{"testing.stacks.org_attacknetruns.yaml", AttacknetRunSpec{}, AttacknetRunStatus{}},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			crd := readCRD(t, test.file)
			if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Schema == nil {
				t.Fatalf("%s must contain exactly one structural version", test.file)
			}
			root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
			compareOwnedFields(t, reflect.TypeOf(test.spec), root.Properties["spec"], "spec")
			compareOwnedFields(t, reflect.TypeOf(test.status), root.Properties["status"], "status")
		})
	}
}

func readCRD(t *testing.T, name string) apixv1.CustomResourceDefinition {
	t.Helper()
	path := filepath.Join("..", "..", "..", "crds", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := utilyaml.ToJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	crd := apixv1.CustomResourceDefinition{}
	if err := json.Unmarshal(jsonData, &crd); err != nil {
		t.Fatal(err)
	}
	return crd
}

func compareOwnedFields(t *testing.T, typ reflect.Type, schema apixv1.JSONSchemaProps, path string) {
	t.Helper()
	typ = dereference(typ)
	if typ.Kind() != reflect.Struct || typ.PkgPath() != apiPackage {
		return
	}
	want := map[string]reflect.Type{}
	for index := range typ.NumField() {
		field := typ.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		want[name] = field.Type
	}
	for name := range schema.Properties {
		if _, ok := want[name]; !ok {
			t.Errorf("%s.%s exists in the CRD but not in %s", path, name, typ.Name())
		}
	}
	for name, fieldType := range want {
		property, ok := schema.Properties[name]
		if !ok {
			t.Errorf("%s.%s exists in %s but not in the CRD", path, name, typ.Name())
			continue
		}
		nested := dereference(fieldType)
		nestedSchema := property
		if nested.Kind() == reflect.Slice {
			nested = dereference(nested.Elem())
			if property.Items == nil || property.Items.Schema == nil {
				if nested.PkgPath() == apiPackage {
					t.Errorf("%s.%s lacks an item schema", path, name)
				}
				continue
			}
			nestedSchema = *property.Items.Schema
		}
		if nested.Kind() == reflect.Struct && nested.PkgPath() == apiPackage {
			compareOwnedFields(t, nested, nestedSchema, path+"."+name)
		}
	}
}

func dereference(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}
