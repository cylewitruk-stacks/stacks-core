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
	"crypto/rand"
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

var (
	scratchPattern = regexp.MustCompile(`^/data/\.attacknet-io-pressure-[a-z0-9-]{1,128}$`)
	escrowPattern  = regexp.MustCompile(`^/data/\.attacknet-capacity-escrow-[a-z0-9-]{1,64}$`)
)

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

func writeEscrow(path string, size int64) error {
	if !escrowPattern.MatchString(path) || size < 1<<20 || size > 64<<30 {
		return errors.New("escrow path or size is outside the bounded capacity contract")
	}
	if err := writeEscrowFile(path, size); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mechanism": "capacity-escrow", "bytes": size, "path": path,
	})
}

func writeEscrowFile(path string, size int64) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
			return errors.New("existing capacity escrow differs from the requested identity")
		}
		return requirePhysicalEscrow(info)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	partial := path + ".partial"
	if info, err := os.Lstat(partial); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("stale capacity escrow partial is not a regular file")
		}
		if err := os.Remove(partial); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create capacity escrow: %w", err)
	}
	complete, published := false, false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(partial)
			if published {
				os.Remove(path)
			}
		}
	}()
	buffer := make([]byte, 1<<20)
	for remaining := size; remaining > 0; {
		if _, err := rand.Read(buffer); err != nil {
			return fmt.Errorf("prepare capacity escrow bytes: %w", err)
		}
		count := int64(len(buffer))
		if remaining < count {
			count = remaining
		}
		written, err := file.Write(buffer[:count])
		if err != nil || int64(written) != count {
			return errors.New("write complete capacity escrow")
		}
		remaining -= count
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync capacity escrow: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(partial, path); err != nil {
		return fmt.Errorf("publish capacity escrow: %w", err)
	}
	published = true
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := requirePhysicalEscrow(info); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	if err := directory.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func requirePhysicalEscrow(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 || int64(stat.Blocks)*512 < info.Size()*9/10 {
		return errors.New("capacity escrow does not have the required physical allocation")
	}
	return nil
}

func run() error {
	var durationSeconds, workers, bytesMiB, writeSizeKiB int
	var scratchPath, escrowPath string
	var escrowBytes int64
	flag.IntVar(&durationSeconds, "duration-seconds", 0, "bounded execution duration")
	flag.IntVar(&workers, "workers", 0, "concurrent fsync workers")
	flag.IntVar(&bytesMiB, "bytes-mib", 0, "total pressure footprint")
	flag.IntVar(&writeSizeKiB, "write-size-kib", 0, "bytes per write in KiB")
	flag.StringVar(&scratchPath, "scratch-path", "", "controller-owned path below /data")
	flag.StringVar(&escrowPath, "escrow-path", "", "session-owned capacity escrow path below /data")
	flag.Int64Var(&escrowBytes, "escrow-bytes", 0, "physically written capacity escrow bytes")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("positional arguments are forbidden")
	}
	if escrowPath != "" || escrowBytes != 0 {
		if scratchPath != "" || durationSeconds != 0 || workers != 0 || bytesMiB != 0 || writeSizeKiB != 0 {
			return errors.New("capacity escrow and pressure arguments are mutually exclusive")
		}
		return writeEscrow(escrowPath, escrowBytes)
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
