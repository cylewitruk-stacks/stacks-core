package fuzzsession

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

var escrowContractPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// EvaluateCapacity makes the deterministic admission decision over trusted
// node and local filesystem observations.
func EvaluateCapacity(policy fuzzplan.CapacityPlan, snapshot CapacitySnapshot) (CapacityReceipt, error) {
	receipt := CapacityReceipt{SchemaVersion: CapacitySchema, Policy: policy, Snapshot: snapshot}
	if len(snapshot.Nodes) == 0 || snapshot.CorpusAvailableBytes < 0 {
		return receipt, errors.New("capacity snapshot is incomplete")
	}
	receipt.Snapshot.Nodes = append([]NodeCapacity(nil), snapshot.Nodes...)
	sort.Slice(receipt.Snapshot.Nodes, func(i, j int) bool {
		return receipt.Snapshot.Nodes[i].Name < receipt.Snapshot.Nodes[j].Name
	})
	for index, node := range receipt.Snapshot.Nodes {
		if node.Name == "" || node.RootAvailableBytes < 0 || node.ImageAvailableBytes < 0 {
			return receipt, fmt.Errorf("capacity node %d is invalid", index)
		}
		switch {
		case node.RootAvailableBytes < policy.MinimumNodeBytes+policy.StorageEscrowBytes:
			receipt.Reason = fmt.Sprintf("node %s root filesystem lacks required headroom", node.Name)
		case node.ImageAvailableBytes < policy.MinimumImageBytes:
			receipt.Reason = fmt.Sprintf("node %s image filesystem lacks required headroom", node.Name)
		}
		if receipt.Reason != "" {
			return sealCapacityReceipt(receipt)
		}
	}
	if snapshot.CorpusAvailableBytes <
		policy.MinimumCorpusBytes+policy.EvidenceEscrowBytes {
		receipt.Reason = "corpus filesystem lacks required headroom"
		return sealCapacityReceipt(receipt)
	}
	receipt.Admitted = true
	return sealCapacityReceipt(receipt)
}

// CreatePhysicalEscrow writes and syncs non-repeating bytes, then verifies
// the file's allocated blocks. Filesystem-wide free-space deltas are not a
// stable proof because unrelated activity and delayed accounting can change
// them while this function runs.
func CreatePhysicalEscrow(root, name string, size int64, contract string) (string, error) {
	if root == "" || name == "" || filepath.Base(name) != name ||
		size < 1 || size > 1<<40 || !escrowContractPattern.MatchString(contract) ||
		name != ".capacity-escrow-"+strings.TrimPrefix(contract, "sha256:") {
		return "", errors.New("escrow root, digest-bound name, contract, and size within 1B..1TiB are required")
	}
	path := filepath.Join(root, name)
	if err := ensureEscrowContract(path, contract); err != nil {
		return "", err
	}
	if info, existingErr := os.Lstat(path); existingErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
			return "", errors.New("existing evidence escrow differs from the requested identity")
		}
		if err := requirePhysicalAllocation(info); err != nil {
			return "", err
		}
		return path, nil
	} else if !errors.Is(existingErr, os.ErrNotExist) {
		return "", existingErr
	}
	partial := path + ".partial"
	if info, partialErr := os.Lstat(partial); partialErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("stale evidence escrow partial is not regular")
		}
		if err := os.Remove(partial); err != nil {
			return "", err
		}
	} else if !errors.Is(partialErr, os.ErrNotExist) {
		return "", partialErr
	}
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create evidence escrow: %w", err)
	}
	success, published := false, false
	defer func() {
		file.Close()
		if !success {
			os.Remove(partial)
			if published {
				os.Remove(path)
			}
		}
	}()
	buffer := make([]byte, 1<<20)
	remaining := size
	for remaining > 0 {
		if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
			return "", fmt.Errorf("prepare non-sparse escrow bytes: %w", err)
		}
		write := int64(len(buffer))
		if remaining < write {
			write = remaining
		}
		if _, err := file.Write(buffer[:write]); err != nil {
			return "", fmt.Errorf("write evidence escrow: %w", err)
		}
		remaining -= write
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync evidence escrow: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(partial, path); err != nil {
		return "", fmt.Errorf("publish evidence escrow: %w", err)
	}
	published = true
	directory, err := os.Open(root)
	if err != nil {
		return "", err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return "", err
	}
	if err := directory.Close(); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		return "", errors.New("published evidence escrow differs from the requested identity")
	}
	if err := requirePhysicalAllocation(info); err != nil {
		return "", err
	}
	success = true
	return path, nil
}

func ensureEscrowContract(path, contract string) error {
	marker := path + ".owner"
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("capacity escrow ownership marker is not a regular file")
		}
		value, err := os.ReadFile(marker)
		if err != nil || string(value) != contract+"\n" {
			return errors.New("capacity escrow ownership marker differs from the session contract")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A published or partial payload without the marker predates this exact
	// session contract and must never be adopted or removed.
	for _, candidate := range []string{path, path + ".partial"} {
		if _, err := os.Lstat(candidate); err == nil {
			return errors.New("unowned capacity escrow payload already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	partial := marker + ".partial"
	if info, err := os.Lstat(partial); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("capacity escrow ownership partial is not a regular file")
		}
		value, readErr := os.ReadFile(partial)
		if readErr != nil || string(value) != contract+"\n" {
			return errors.New("incomplete capacity escrow ownership marker requires operator inspection")
		}
		if err := os.Rename(partial, marker); err != nil {
			return fmt.Errorf("recover capacity escrow ownership marker: %w", err)
		}
		if err := syncEscrowDirectory(path); err != nil {
			return err
		}
		return ensureEscrowContract(path, contract)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create capacity escrow ownership marker: %w", err)
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(partial)
		}
	}()
	if _, err := io.WriteString(file, contract+"\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(partial, marker); err != nil {
		return fmt.Errorf("publish capacity escrow ownership marker: %w", err)
	}
	if err := syncEscrowDirectory(path); err != nil {
		return err
	}
	complete = true
	return nil
}

// ReleasePhysicalEscrow removes only the exact regular non-symlink file.
func ReleasePhysicalEscrow(path string) error {
	if _, err := escrowContract(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to release non-regular escrow path")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(path + ".owner"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncEscrowDirectory(path)
}

// PhysicalEscrowIdentity returns a stable identity for an exact local escrow
// file without hashing its potentially large content.
func PhysicalEscrowIdentity(path string) (string, error) {
	contract, err := escrowContract(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capacity escrow is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("filesystem does not expose an escrow inode")
	}
	if err := requirePhysicalAllocation(info); err != nil {
		return "", err
	}
	return fmt.Sprintf("contract:%s:inode:%d:size:%d:blocks:%d", contract, stat.Ino, info.Size(), stat.Blocks), nil
}

func escrowContract(path string) (string, error) {
	marker := path + ".owner"
	info, err := os.Lstat(marker)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 72 {
		return "", errors.New("capacity escrow ownership marker is invalid")
	}
	value, err := os.ReadFile(marker)
	contract := strings.TrimSuffix(string(value), "\n")
	if err != nil || string(value) != contract+"\n" || !escrowContractPattern.MatchString(contract) ||
		filepath.Base(path) != ".capacity-escrow-"+strings.TrimPrefix(contract, "sha256:") {
		return "", errors.New("capacity escrow ownership marker is invalid")
	}
	return contract, nil
}

func syncEscrowDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func requirePhysicalAllocation(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 || int64(stat.Blocks)*512 < info.Size()*9/10 {
		return errors.New("capacity escrow does not have the required physical allocation")
	}
	return nil
}

func availableBytes(path string) (int64, error) {
	var status syscall.Statfs_t
	if err := syscall.Statfs(path, &status); err != nil {
		return 0, fmt.Errorf("read filesystem capacity: %w", err)
	}
	if status.Bavail > uint64(^uint64(0)>>1)/uint64(status.Bsize) {
		return 0, errors.New("filesystem capacity exceeds supported integer range")
	}
	return int64(status.Bavail) * int64(status.Bsize), nil
}

// LocalAvailableBytes returns current available bytes for a corpus path.
func LocalAvailableBytes(path string) (int64, error) { return availableBytes(path) }

func sealCapacityReceipt(receipt CapacityReceipt) (CapacityReceipt, error) {
	receipt.Digest = ""
	digest, err := canonical.Digest(receipt)
	if err != nil {
		return CapacityReceipt{}, err
	}
	receipt.Digest = digest
	return receipt, nil
}
