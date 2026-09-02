package fuzzcorpus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

// Lock is one explicitly owned corpus single-writer lock.
type Lock struct {
	path   string
	record LockRecord
	closed bool
}

// AcquireLock creates the corpus lock without stealing an existing owner.
func (store *Store) AcquireLock(owner string) (*Lock, error) {
	if owner == "" || len(owner) > 256 {
		return nil, errors.New("bounded corpus lock owner is required")
	}
	record := LockRecord{
		SchemaVersion: "stacks-attacknet-corpus-lock/v1",
		Owner:         owner, ProcessID: os.Getpid(), AcquiredAt: store.now().UTC(),
	}
	data, err := canonical.Marshal(record)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(store.root, ".writer.lock")
	// Publish the complete, synced record with one exclusive link. A process
	// dying while writing the sibling temporary file cannot leave a partial
	// lock at the authoritative path.
	temporary, err := os.CreateTemp(filepath.Dir(store.root), ".attacknet-corpus-lock-*")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("corpus is locked; inspect and explicitly break %s", path)
		}
		return nil, err
	}
	if err := syncDirectory(store.root); err != nil {
		return nil, err
	}
	lock := &Lock{path: path, record: record}
	if err := store.recoverPendingWrites(); err != nil {
		_ = lock.Release()
		return nil, err
	}
	return lock, nil
}

// Release removes only this exact lock record.
func (lock *Lock) Release() error {
	if lock == nil || lock.closed {
		return errors.New("corpus lock is not active")
	}
	data, err := readRegularFile(lock.path, maximumMetadataBytes)
	if err != nil {
		return err
	}
	var current LockRecord
	if err := json.Unmarshal(data, &current); err != nil || current != lock.record {
		return errors.New("corpus lock identity changed; refusing release")
	}
	if err := os.Remove(lock.path); err != nil {
		return err
	}
	lock.closed = true
	if err := syncDirectory(filepath.Dir(lock.path)); err != nil {
		return err
	}
	return nil
}

// BreakLock removes one exact stale record and writes an audit receipt.
func (store *Store) BreakLock(expected LockRecord, reason string) error {
	if expected.SchemaVersion == "" || reason == "" || len(reason) > 512 {
		return errors.New("expected lock identity and bounded reason are required")
	}
	path := filepath.Join(store.root, ".writer.lock")
	data, err := readRegularFile(path, maximumMetadataBytes)
	if err != nil {
		return err
	}
	var current LockRecord
	if err := json.Unmarshal(data, &current); err != nil || current != expected {
		return errors.New("corpus lock does not match expected stale owner")
	}
	receipt := struct {
		SchemaVersion string     `json:"schemaVersion"`
		Broken        LockRecord `json:"broken"`
		Reason        string     `json:"reason"`
		BrokenAt      time.Time  `json:"brokenAt"`
	}{
		SchemaVersion: "stacks-attacknet-corpus-lock-break/v1",
		Broken:        current, Reason: reason, BrokenAt: store.now().UTC(),
	}
	if _, err := store.PutAudit("corpus-lock-break", receipt); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(store.root)
}

// LockRecord returns the exact current owner of the local writer lock.
func (store *Store) LockRecord() (LockRecord, error) {
	data, err := readRegularFile(filepath.Join(store.root, ".writer.lock"), maximumMetadataBytes)
	if err != nil {
		return LockRecord{}, err
	}
	var record LockRecord
	if json.Unmarshal(data, &record) != nil || record.SchemaVersion != "stacks-attacknet-corpus-lock/v1" ||
		record.Owner == "" || record.ProcessID < 1 || record.AcquiredAt.IsZero() {
		return LockRecord{}, errors.New("corpus lock record is invalid")
	}
	return record, nil
}
