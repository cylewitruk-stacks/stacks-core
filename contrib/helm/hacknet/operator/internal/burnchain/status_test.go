package burnchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStatusSinkWritesCompatibilityProjectionAtomically(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "status.env")
	height, generation := uint64(240), uint64(7)
	err := (FileStatusSink{Path: path}).Write(Status{
		State: "paused", BitcoinHeight: &height, PolicyGeneration: &generation,
		Detail: "safe\nvalue", UpdatedAt: time.Unix(1234, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "state=paused\nbitcoin_height=240\npolicy_generation=7\ndetail=safe-value\nupdated_at=1234\n"
	if string(contents) != want {
		t.Fatalf("status mismatch:\n%s\nwant:\n%s", contents, want)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "status.env") {
		t.Fatalf("temporary status artifacts survived: %#v", entries)
	}
}
