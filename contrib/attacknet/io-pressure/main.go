// attacknet-io-pressure is a deliberately narrow disk-pressure workload.
//
// The run controller, not a FaultCampaign author, selects this executable and
// supplies bounded numeric arguments. Every worker opens a file on the actor's
// data PVC, immediately unlinks it, removes the now-empty campaign directory,
// and then repeatedly writes and fsyncs the still-open inode. Consequently a
// kill cannot leave a named payload behind on the actor volume.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
)

var scratchPattern = regexp.MustCompile(`^/data/\.attacknet-io-pressure-[a-z0-9-]{1,128}$`)

type result struct {
	Mechanism       string `json:"mechanism"`
	Workers         int    `json:"workers"`
	BytesMiB        int    `json:"bytesMiB"`
	WriteSizeKiB    int    `json:"writeSizeKiB"`
	DurationSeconds int    `json:"durationSeconds"`
	Writes          uint64 `json:"writes"`
	Fsyncs          uint64 `json:"fsyncs"`
}

func bounded(value, minimum, maximum int, name string) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%s must be in %d..%d", name, minimum, maximum)
	}
	return nil
}

func worker(ctx context.Context, file *os.File, capacity, writeSize int64) (uint64, error) {
	buffer := make([]byte, writeSize)
	for index := range buffer {
		buffer[index] = byte((index * 31) % 251)
	}
	var writes uint64
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return writes, nil
		default:
		}
		if offset+writeSize > capacity {
			if _, err := file.Seek(0, 0); err != nil {
				return writes, err
			}
			offset = 0
		}
		written, err := file.Write(buffer)
		if err != nil {
			return writes, err
		}
		if written != len(buffer) {
			return writes, errors.New("short pressure write")
		}
		if err := file.Sync(); err != nil {
			return writes, err
		}
		writes++
		offset += int64(written)
	}
}

func run() error {
	var durationSeconds, workers, bytesMiB, writeSizeKiB int
	var scratchPath string
	flag.IntVar(&durationSeconds, "duration-seconds", 0, "bounded execution duration")
	flag.IntVar(&workers, "workers", 0, "concurrent fsync workers")
	flag.IntVar(&bytesMiB, "bytes-mib", 0, "total pressure footprint")
	flag.IntVar(&writeSizeKiB, "write-size-kib", 0, "bytes per write in KiB")
	flag.StringVar(&scratchPath, "scratch-path", "", "controller-owned path below /data")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("positional arguments are forbidden")
	}
	for _, check := range []error{
		bounded(durationSeconds, 1, 300, "duration-seconds"),
		bounded(workers, 1, 4, "workers"),
		bounded(bytesMiB, 16, 512, "bytes-mib"),
		bounded(writeSizeKiB, 4, 1024, "write-size-kib"),
	} {
		if check != nil {
			return check
		}
	}
	if !scratchPattern.MatchString(scratchPath) {
		return errors.New("scratch-path is outside the controller-owned /data namespace")
	}
	if writeSizeKiB > bytesMiB*1024 {
		return errors.New("write-size-kib exceeds bytes-mib")
	}
	if err := os.Mkdir(scratchPath, 0o770); err != nil {
		return fmt.Errorf("create scratch directory: %w", err)
	}
	// A best-effort defer covers failures during preparation. The normal path
	// removes every directory entry before disk pressure begins.
	defer os.RemoveAll(scratchPath)
	files := make([]*os.File, 0, workers)
	for index := 0; index < workers; index++ {
		name := filepath.Join(scratchPath, fmt.Sprintf("worker-%d", index))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open worker file: %w", err)
		}
		if err := os.Remove(name); err != nil {
			file.Close()
			return fmt.Errorf("unlink worker file: %w", err)
		}
		files = append(files, file)
	}
	if err := os.Remove(scratchPath); err != nil {
		return fmt.Errorf("remove empty scratch directory: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(durationSeconds)*time.Second)
	defer cancel()
	capacity := int64(bytesMiB) * 1024 * 1024 / int64(workers)
	writeSize := int64(writeSizeKiB) * 1024
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	writesByWorker := make(chan uint64, workers)
	for _, file := range files {
		wait.Add(1)
		go func(file *os.File) {
			defer wait.Done()
			writes, err := worker(ctx, file, capacity, writeSize)
			writesByWorker <- writes
			errorsByWorker <- err
		}(file)
	}
	wait.Wait()
	close(writesByWorker)
	close(errorsByWorker)
	var writes uint64
	for count := range writesByWorker {
		writes += count
	}
	for err := range errorsByWorker {
		if err != nil {
			return fmt.Errorf("pressure worker: %w", err)
		}
	}
	for _, file := range files {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close pressure file: %w", err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result{
		Mechanism: "controller-owned-io-pressure-pod", Workers: workers,
		BytesMiB: bytesMiB, WriteSizeKiB: writeSizeKiB,
		DurationSeconds: durationSeconds, Writes: writes, Fsyncs: writes,
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
