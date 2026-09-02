// Package imagearchive reads the platform runtime identities emitted by
// Docker's OCI-compatible image archives.
package imagearchive

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
}

// PlatformConfigIDs binds requested references to the runtime config digests
// contained in a single-platform Docker archive. Expected IDs disambiguate
// digest-only references, for which Docker intentionally emits no RepoTags.
func PlatformConfigIDs(archive string, refs []string, expected map[string]string) (map[string]string, error) {
	manifest, err := readManifest(archive)
	if err != nil {
		return nil, err
	}
	byReference := make(map[string]string)
	available := make(map[string]struct{}, len(manifest))
	for _, entry := range manifest {
		config := strings.TrimSuffix(path.Base(entry.Config), ".json")
		imageID := "sha256:" + config
		if !digestPattern.MatchString(imageID) {
			return nil, fmt.Errorf("exported image config %q is not an immutable digest", entry.Config)
		}
		available[imageID] = struct{}{}
		for _, ref := range entry.RepoTags {
			normalized := NormalizeReference(ref)
			if previous := byReference[normalized]; previous != "" && previous != imageID {
				return nil, fmt.Errorf("exported image reference %s resolves to multiple runtime image IDs", normalized)
			}
			byReference[normalized] = imageID
		}
	}
	result := make(map[string]string, len(refs))
	for _, ref := range refs {
		imageID := byReference[NormalizeReference(ref)]
		if imageID == "" {
			candidate := expected[ref]
			if candidate == "" && len(refs) == 1 && len(available) == 1 {
				for candidate = range available {
				}
			}
			if _, ok := available[candidate]; ok {
				imageID = candidate
			}
		}
		if imageID == "" {
			return nil, fmt.Errorf("exported image archive does not bind %s to a platform config", ref)
		}
		if candidate := expected[ref]; candidate != "" && candidate != imageID {
			return nil, fmt.Errorf("exported image archive binds %s to %s, expected %s", ref, imageID, candidate)
		}
		result[ref] = imageID
	}
	return result, nil
}

func readManifest(archive string) ([]dockerManifestEntry, error) {
	file, err := os.Open(archive)
	if err != nil {
		return nil, fmt.Errorf("open exported image archive: %w", err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("exported image archive has no Docker manifest")
		}
		if err != nil {
			return nil, fmt.Errorf("read exported image archive: %w", err)
		}
		if path.Clean(header.Name) != "manifest.json" {
			continue
		}
		if header.Size < 1 || header.Size > 16<<20 {
			return nil, fmt.Errorf("exported image manifest has invalid size %d", header.Size)
		}
		var manifest []dockerManifestEntry
		if err := json.NewDecoder(io.LimitReader(reader, header.Size)).Decode(&manifest); err != nil {
			return nil, fmt.Errorf("decode exported image manifest: %w", err)
		}
		if len(manifest) == 0 {
			return nil, fmt.Errorf("exported image archive has no Docker manifest")
		}
		return manifest, nil
	}
}

// NormalizeReference applies containerd's canonical Docker Hub naming.
func NormalizeReference(ref string) string {
	if !strings.Contains(ref, "/") {
		return "docker.io/library/" + ref
	}
	first := strings.SplitN(ref, "/", 2)[0]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return ref
	}
	return "docker.io/" + ref
}
