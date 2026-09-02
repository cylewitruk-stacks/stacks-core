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
	if !escrowPattern.MatchString("/data/.attacknet-capacity-escrow-0123456789ab") ||
		escrowPattern.MatchString("/tmp/.attacknet-capacity-escrow-0123456789ab") {
		t.Fatal("capacity escrow namespace is not exact")
	}
}

func TestWriteEscrowFileIsAtomicAndResumable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "escrow")
	const size = int64(1 << 20)
	if err := writeEscrowFile(path, size); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		t.Fatalf("published escrow = %#v, %v", info, err)
	}
	if _, err := os.Lstat(path + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("partial escrow survived publication: %v", err)
	}
	if err := writeEscrowFile(path, size); err != nil {
		t.Fatalf("exact escrow was not resumable: %v", err)
	}
	if err := os.Truncate(path, size-1); err != nil {
		t.Fatal(err)
	}
	if err := writeEscrowFile(path, size); err == nil {
		t.Fatal("mismatched existing escrow was adopted")
	}
	sparse := filepath.Join(t.TempDir(), "sparse")
	file, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeEscrowFile(sparse, size); err == nil {
		t.Fatal("sparse existing escrow was adopted")
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
