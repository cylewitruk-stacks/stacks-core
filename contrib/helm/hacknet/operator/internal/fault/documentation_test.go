package fault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestFaultReferenceCoversMechanismRegistry keeps the operator-facing catalog
// synchronized with the closed fault-mechanism registry.
func TestFaultReferenceCoversMechanismRegistry(t *testing.T) {
	t.Parallel()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fault package source")
	}
	directory := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../../attacknet/docs/reference/faults"))
	index := readFaultReference(t, filepath.Join(directory, "README.md"))

	expected := map[string]bool{"README.md": true}
	for _, definition := range registeredMechanisms() {
		name := definition.FaultType + ".md"
		expected[name] = true
		if !strings.Contains(index, fmt.Sprintf("(%s)", name)) {
			t.Errorf("fault reference index does not link %s", name)
		}

		document := readFaultReference(t, filepath.Join(directory, name))
		if !strings.Contains(document, fmt.Sprintf("| Fault type | `%s` |", definition.FaultType)) {
			t.Errorf("%s does not declare fault type %q", name, definition.FaultType)
		}
		if !strings.Contains(document, "`"+definition.MutationKind+"`") {
			t.Errorf("%s does not identify mutation kind %q", name, definition.MutationKind)
		}
		if len(definition.AllowedActions) == 0 && !strings.Contains(document, "| Action | Omitted |") {
			t.Errorf("%s does not state that action is omitted", name)
		}
		for action := range definition.AllowedActions {
			if !strings.Contains(document, "`"+action+"`") {
				t.Errorf("%s does not document action %q", name, action)
			}
		}
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read fault reference directory: %v", err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".md" {
			actual = append(actual, entry.Name())
		}
	}
	sort.Strings(actual)
	for _, name := range actual {
		if !expected[name] {
			t.Errorf("fault reference contains stale or unregistered page %s", name)
		}
		delete(expected, name)
	}
	for name := range expected {
		t.Errorf("fault reference is missing %s", name)
	}
}

// readFaultReference loads one reference document or fails the calling test.
func readFaultReference(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
