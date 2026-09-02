package fuzzcorpus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const journalSchema = "stacks-attacknet-fuzz-journal-record/v1"

// Journal owns the immutable event chain for one session.
type Journal struct {
	store   *Store
	root    string
	records []JournalRecord
}

// OpenJournal verifies and opens one session journal.
func (store *Store) OpenJournal(sessionDigest string) (*Journal, error) {
	if !digestPattern.MatchString(sessionDigest) {
		return nil, errors.New("session digest must be SHA-256")
	}
	root := filepath.Join(
		store.root, "sessions", strings.TrimPrefix(sessionDigest, "sha256:"), "journal",
	)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	journal := &Journal{store: store, root: root}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("unexpected journal entry %s", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := readRegularFile(filepath.Join(root, name), maximumMetadataBytes)
		if err != nil {
			return nil, err
		}
		var record JournalRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("decode journal record %s: %w", name, err)
		}
		if err := journal.validateNext(record, name); err != nil {
			return nil, err
		}
		journal.records = append(journal.records, record)
	}
	return journal, nil
}

// Records returns a defensive copy of the verified chain.
func (journal *Journal) Records() []JournalRecord {
	result := make([]JournalRecord, len(journal.records))
	copy(result, journal.records)
	return result
}

// Append persists one event before the caller performs its next side effect.
func (journal *Journal) Append(record JournalRecord) (JournalRecord, error) {
	if journal == nil || journal.store == nil {
		return JournalRecord{}, errors.New("journal is required")
	}
	record.SchemaVersion = journalSchema
	record.Sequence = int64(len(journal.records) + 1)
	record.PriorDigest = ""
	if len(journal.records) != 0 {
		record.PriorDigest = journal.records[len(journal.records)-1].Digest
	}
	record.OccurredAt = journal.store.now().UTC()
	record.Digest = ""
	if err := validateJournalPayload(record); err != nil {
		return JournalRecord{}, err
	}
	digest, err := canonicalRecordDigest(record)
	if err != nil {
		return JournalRecord{}, err
	}
	record.Digest = digest
	name := fmt.Sprintf("%08d-%s.json", record.Sequence, strings.TrimPrefix(digest, "sha256:"))
	if err := journal.store.writeCanonical(filepath.Join(journal.root, name), record, true); err != nil {
		return JournalRecord{}, err
	}
	journal.records = append(journal.records, record)
	return record, nil
}

func (journal *Journal) validateNext(record JournalRecord, name string) error {
	if record.SchemaVersion != journalSchema ||
		record.Sequence != int64(len(journal.records)+1) ||
		!digestPattern.MatchString(record.Digest) {
		return fmt.Errorf("journal record %s has invalid sequence or envelope", name)
	}
	wantPrior := ""
	if len(journal.records) != 0 {
		wantPrior = journal.records[len(journal.records)-1].Digest
	}
	if record.PriorDigest != wantPrior {
		return fmt.Errorf("journal record %s breaks the hash chain", name)
	}
	digest, err := canonicalRecordDigest(record)
	if err != nil || digest != record.Digest {
		return fmt.Errorf("journal record %s digest mismatch", name)
	}
	wantName := fmt.Sprintf("%08d-%s.json", record.Sequence, strings.TrimPrefix(record.Digest, "sha256:"))
	if name != wantName {
		return fmt.Errorf("journal record %s is stored under the wrong identity", name)
	}
	return validateJournalPayload(record)
}

func canonicalRecordDigest(record JournalRecord) (string, error) {
	record.Digest = ""
	return canonical.Digest(record)
}

func validateJournalPayload(record JournalRecord) error {
	if record.Kind == "" || len(record.Kind) > 128 ||
		record.Phase == "" || len(record.Phase) > 128 ||
		record.TrialOrdinal < 0 || record.TrialOrdinal > 256 ||
		len(record.AttemptID) > 63 ||
		len(record.Resources) > 64 || len(record.Artifacts) > 4096 {
		return errors.New("journal record is incomplete or unbounded")
	}
	encoded, err := canonical.Marshal(record)
	if err != nil || len(encoded) > maximumMetadataBytes {
		return errors.New("journal record metadata is invalid or exceeds its bound")
	}
	for _, resource := range record.Resources {
		if resource.APIVersion == "" || resource.Kind == "" ||
			resource.Namespace == "" || resource.Name == "" {
			return errors.New("journal resource identity is incomplete")
		}
	}
	for _, artifact := range record.Artifacts {
		if err := validateObjectReference(artifact); err != nil {
			return errors.New("journal artifact reference is invalid")
		}
	}
	return nil
}
