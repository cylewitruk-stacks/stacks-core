package attacknetcli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanAttacknetExamplesAreStrictV1Beta1YAML(t *testing.T) {
	directory := filepath.Join("..", "..", "..", "..", "..", "attacknet", "examples")
	var yamlPaths []string
	var jsonPaths []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			yamlPaths = append(yamlPaths, path)
		case ".json":
			jsonPaths = append(jsonPaths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(yamlPaths) < 12 {
		t.Fatalf("found %d YAML examples, want at least 12", len(yamlPaths))
	}
	for _, path := range yamlPaths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := DecodeSubmission(data, "hacknet-system"); err != nil {
				t.Fatalf("strict v1beta1 validation: %v", err)
			}
		})
	}
	for _, path := range jsonPaths {
		if !strings.HasSuffix(path, ".plan.json") {
			t.Fatalf("human Kubernetes example must be YAML; unexpected JSON file %s", path)
		}
	}
}
