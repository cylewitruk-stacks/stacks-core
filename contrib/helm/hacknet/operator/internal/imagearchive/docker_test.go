package imagearchive

import (
	"archive/tar"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformConfigIDsResolvesTaggedAndDigestOnlyEntries(t *testing.T) {
	t.Parallel()
	const taggedID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const digestID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const digestRef = "example/immutable@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	archive := writeArchive(t, []map[string]any{
		{"Config": "blobs/sha256/" + strings.TrimPrefix(taggedID, "sha256:"), "RepoTags": []string{"example:tagged"}},
		{"Config": "blobs/sha256/" + strings.TrimPrefix(digestID, "sha256:"), "RepoTags": nil},
	})
	ids, err := PlatformConfigIDs(archive, []string{"example:tagged", digestRef}, map[string]string{digestRef: digestID})
	if err != nil {
		t.Fatal(err)
	}
	if ids["example:tagged"] != taggedID || ids[digestRef] != digestID {
		t.Fatalf("unexpected platform IDs: %#v", ids)
	}
	wrongID := "sha256:" + strings.Repeat("f", 64)
	if _, err := PlatformConfigIDs(archive, []string{digestRef}, map[string]string{digestRef: wrongID}); err == nil {
		t.Fatal("digest-only reference accepted the wrong expected config identity")
	}
}

func TestPlatformConfigIDsUsesSingleEntryForPreparation(t *testing.T) {
	t.Parallel()
	const imageID = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const ref = "example/immutable@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	archive := writeArchive(t, []map[string]any{{
		"Config": "blobs/sha256/" + strings.TrimPrefix(imageID, "sha256:"), "RepoTags": nil,
	}})
	ids, err := PlatformConfigIDs(archive, []string{ref}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ids[ref] != imageID {
		t.Fatalf("single digest-only entry resolved to %s", ids[ref])
	}
}

func writeArchive(t *testing.T, manifest []map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(encoded))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
