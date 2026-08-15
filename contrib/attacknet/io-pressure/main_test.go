package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBoundsAndScratchNamespace(t *testing.T) {
	if bounded(1, 1, 4, "workers") != nil || bounded(5, 1, 4, "workers") == nil {
		t.Fatal("bounded profile validation is not fail closed")
	}
	for _, value := range []string{
		"/tmp/.attacknet-io-pressure-uid",
		"/data/other",
		"/data/.attacknet-io-pressure-../../escape",
	} {
		if scratchPattern.MatchString(value) {
			t.Fatalf("unsafe scratch path admitted: %s", value)
		}
	}
	if !scratchPattern.MatchString("/data/.attacknet-io-pressure-uid-campaign-123") {
		t.Fatal("controller-owned scratch path rejected")
	}
}

func TestWorkerUsesAnUnlinkedFileAndStops(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, "pressure")
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	writes, err := worker(ctx, file, 64*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}
	if writes == 0 {
		t.Fatal("worker performed no write+fsync operation")
	}
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("unlinked pressure path became visible: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
