package fuzzcorpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const maximumMetadataBytes = 8 << 20

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var digestPrefixPattern = regexp.MustCompile(`^[0-9a-f]{2}$`)
var auditKindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var pendingWritePattern = regexp.MustCompile(`^\.attacknet-corpus-[0-9]+$`)

// Store is one initialized content-addressed corpus.
type Store struct {
	root         string
	maximumBytes int64
	now          func() time.Time
	writeMu      sync.Mutex
}

// OpenExisting reads the configured bound from an initialized corpus.
func OpenExisting(root string, now func() time.Time) (*Store, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve corpus root: %w", err)
	}
	data, err := readRegularFile(filepath.Join(absolute, "corpus.json"), maximumMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read corpus metadata: %w", err)
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil ||
		!validMetadata(data, metadata.MaximumBytes) || metadata.MaximumBytes < 1 ||
		metadata.MaximumBytes > 1<<50 {
		return nil, errors.New("existing corpus metadata is invalid")
	}
	return Open(absolute, metadata.MaximumBytes, now)
}

// Open initializes or verifies a corpus root.
func Open(root string, maximumBytes int64, now func() time.Time) (*Store, error) {
	if root == "" || maximumBytes < 1 || maximumBytes > 1<<50 {
		return nil, errors.New("corpus root and maximum bytes within 1..1PiB are required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve corpus root: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	for _, directory := range []string{
		absolute, filepath.Join(absolute, "objects", "sha256"),
		filepath.Join(absolute, "entries"), filepath.Join(absolute, "sessions"),
		filepath.Join(absolute, "reports"), filepath.Join(absolute, "audit"),
		filepath.Join(absolute, ".pending"),
	} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return nil, fmt.Errorf("create corpus directory: %w", err)
		}
	}
	store := &Store{root: absolute, maximumBytes: maximumBytes, now: now}
	metadataPath := filepath.Join(absolute, "corpus.json")
	data, err := readRegularFile(metadataPath, maximumMetadataBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		metadata := Metadata{
			SchemaVersion: CorpusSchema, MaximumBytes: maximumBytes,
			CreatedAt: now().UTC(),
		}
		if err := store.writeCanonical(metadataPath, metadata, true); err != nil {
			// Another initializer may have published the same immutable corpus
			// identity after our absence check. Accept only a complete metadata
			// record with the requested bound.
			concurrent, readErr := readRegularFile(metadataPath, maximumMetadataBytes)
			if readErr != nil || !validMetadata(concurrent, maximumBytes) {
				return nil, err
			}
		}
	case err != nil:
		return nil, fmt.Errorf("read corpus metadata: %w", err)
	default:
		if !validMetadata(data, maximumBytes) {
			return nil, errors.New("existing corpus metadata is invalid or uses another size bound")
		}
	}
	return store, nil
}

// validMetadata checks the immutable corpus identity and initialization time.
func validMetadata(data []byte, maximumBytes int64) bool {
	var metadata Metadata
	return len(data) <= maximumMetadataBytes && json.Unmarshal(data, &metadata) == nil &&
		metadata.SchemaVersion == CorpusSchema && metadata.MaximumBytes == maximumBytes &&
		!metadata.CreatedAt.IsZero()
}

// Root returns the absolute corpus root.
func (store *Store) Root() string { return store.root }

// PutObject stores immutable bytes and returns their reference.
func (store *Store) PutObject(name, contentType string, data []byte) (ObjectReference, error) {
	if name == "" || len(name) > 256 || data == nil {
		return ObjectReference{}, errors.New("object name and supplied bytes are required")
	}
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	path, err := store.objectPath(digest)
	if err != nil {
		return ObjectReference{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return ObjectReference{}, err
	}
	if err := store.writeBytes(path, data, true); err != nil {
		return ObjectReference{}, err
	}
	return ObjectReference{Name: name, Digest: digest, Size: int64(len(data)), ContentType: contentType}, nil
}

// PutCanonicalObject encodes one bounded integer-only artifact.
func (store *Store) PutCanonicalObject(name, contentType string, value any) (ObjectReference, error) {
	data, err := canonical.Marshal(value)
	if err != nil {
		return ObjectReference{}, err
	}
	return store.PutObject(name, contentType, data)
}

// PutExactIntegerObject stores a canonical Go-owned typed artifact whose JSON
// contract includes signed 64-bit integers outside JavaScript's safe range.
func (store *Store) PutExactIntegerObject(name, contentType string, value any) (ObjectReference, error) {
	data, err := canonical.MarshalExactIntegers(value)
	if err != nil {
		return ObjectReference{}, err
	}
	return store.PutObject(name, contentType, data)
}

// ReadObject verifies and returns immutable bytes.
func (store *Store) ReadObject(reference ObjectReference) ([]byte, error) {
	if err := validateObjectReference(reference); err != nil {
		return nil, err
	}
	if reference.Size > store.maximumBytes {
		return nil, fmt.Errorf("object %s exceeds corpus maximum bytes", reference.Digest)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		return nil, err
	}
	data, err := readRegularFile(path, store.maximumBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != reference.Size {
		return nil, fmt.Errorf("object %s size mismatch", reference.Digest)
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != reference.Digest {
		return nil, fmt.Errorf("object %s digest mismatch", reference.Digest)
	}
	return data, nil
}

// PutReportPointer publishes one immutable report reference under its session
// identity. Repeating the exact write is safe; substitution is rejected.
func (store *Store) PutReportPointer(sessionDigest string, report ObjectReference) error {
	if !digestPattern.MatchString(sessionDigest) || report.Name == "" {
		return errors.New("session digest and report reference are required")
	}
	if _, err := store.ReadObject(report); err != nil {
		return fmt.Errorf("verify session report: %w", err)
	}
	path := filepath.Join(store.root, "reports", strings.TrimPrefix(sessionDigest, "sha256:")+".json")
	return store.writeCanonical(path, ReportPointer{
		SchemaVersion: ReportPointerSchema, SessionDigest: sessionDigest, Report: report,
	}, true)
}

// Report returns and verifies the immutable report reference for a session.
func (store *Store) Report(sessionDigest string) (ReportPointer, error) {
	if !digestPattern.MatchString(sessionDigest) {
		return ReportPointer{}, errors.New("session digest must be SHA-256")
	}
	path := filepath.Join(store.root, "reports", strings.TrimPrefix(sessionDigest, "sha256:")+".json")
	data, err := readRegularFile(path, maximumMetadataBytes)
	if err != nil {
		return ReportPointer{}, err
	}
	var pointer ReportPointer
	if json.Unmarshal(data, &pointer) != nil || pointer.SchemaVersion != ReportPointerSchema ||
		pointer.SessionDigest != sessionDigest {
		return ReportPointer{}, errors.New("session report pointer is invalid")
	}
	if _, err := store.ReadObject(pointer.Report); err != nil {
		return ReportPointer{}, err
	}
	return pointer, nil
}

// PutAudit stores one immutable administrative receipt outside the session
// report namespace and returns its content-addressed record.
func (store *Store) PutAudit(kind string, value any) (ObjectReference, error) {
	if !auditKindPattern.MatchString(kind) {
		return ObjectReference{}, errors.New("audit kind must be a bounded DNS label")
	}
	record, err := store.PutCanonicalObject(kind, "application/json", value)
	if err != nil {
		return ObjectReference{}, err
	}
	path := filepath.Join(store.root, "audit", kind+"-"+strings.TrimPrefix(record.Digest, "sha256:")+".json")
	if err := store.writeCanonical(path, AuditPointer{
		SchemaVersion: AuditPointerSchema, Kind: kind, Record: record,
	}, true); err != nil {
		return ObjectReference{}, err
	}
	return record, nil
}

// SemanticFingerprint hashes normalized trusted outcome dimensions.
func SemanticFingerprint(input FingerprintInput) (string, error) {
	if input.SchemaVersion != FingerprintSchema ||
		input.Phase == "" || input.Reason == "" || input.Attribution == "" {
		return "", errors.New("semantic fingerprint input is incomplete or invalid")
	}
	var err error
	input.AssertionResults, err = sortedUnique(input.AssertionResults)
	if err != nil {
		return "", fmt.Errorf("assertion results: %w", err)
	}
	input.MechanismFamilies, err = sortedUnique(input.MechanismFamilies)
	if err != nil {
		return "", fmt.Errorf("mechanism families: %w", err)
	}
	return canonical.Digest(input)
}

// PutEntry verifies and stores one immutable corpus manifest.
func (store *Store) PutEntry(entry Entry) (Entry, error) {
	entry = normalizeEntry(entry)
	if err := store.validateEntry(entry); err != nil {
		return Entry{}, err
	}
	view := entry
	view.Digest = ""
	digest, err := canonical.Digest(view)
	if err != nil {
		return Entry{}, err
	}
	entry.Digest = digest
	path := filepath.Join(
		store.root, "entries", strings.TrimPrefix(entry.Fingerprint, "sha256:"),
		strings.TrimPrefix(entry.Digest, "sha256:")+".json",
	)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return Entry{}, err
	}
	if err := store.writeCanonical(path, entry, true); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// normalizeEntry returns an entry with a deterministic object inventory.
func normalizeEntry(entry Entry) Entry {
	entry.Objects = append([]ObjectReference(nil), entry.Objects...)
	sort.Slice(entry.Objects, func(i, j int) bool {
		if entry.Objects[i].Name == entry.Objects[j].Name {
			return entry.Objects[i].Digest < entry.Objects[j].Digest
		}
		return entry.Objects[i].Name < entry.Objects[j].Name
	})
	return entry
}

// validateEntry applies every persisted entry invariant and object binding.
func (store *Store) validateEntry(entry Entry) error {
	if entry.SchemaVersion != EntrySchema ||
		!digestPattern.MatchString(entry.Fingerprint) ||
		!digestPattern.MatchString(entry.SessionDigest) ||
		entry.TrialOrdinal < 1 || entry.SourceRun == "" ||
		len(entry.ReplayCommand) == 0 || len(entry.ReplayCommand) > 64 ||
		len(entry.Objects) == 0 || len(entry.Objects) > 4096 ||
		len(entry.Attempts) == 0 || len(entry.Attempts) > 4096 {
		return errors.New("corpus entry is incomplete or unbounded")
	}
	encoded, err := canonical.Marshal(entry)
	if err != nil || len(encoded) > maximumMetadataBytes {
		return errors.New("corpus entry metadata is invalid or exceeds its bound")
	}
	switch entry.Classification {
	case "Clean", "NetworkFailureCandidate", "ConfirmedNetworkFailure",
		"NotReproduced", "Inconclusive", "HarnessFailed":
	default:
		return errors.New("corpus entry classification is unsupported")
	}
	if len(entry.ReplayCommand) < 4 || entry.ReplayCommand[0] != "attacknet" ||
		entry.ReplayCommand[1] != "corpus" || entry.ReplayCommand[2] != "replay" {
		return errors.New("corpus replay command must use the typed attacknet replay surface")
	}
	if !sort.SliceIsSorted(entry.Objects, func(i, j int) bool {
		if entry.Objects[i].Name == entry.Objects[j].Name {
			return entry.Objects[i].Digest < entry.Objects[j].Digest
		}
		return entry.Objects[i].Name < entry.Objects[j].Name
	}) {
		return errors.New("corpus object inventory is not in canonical order")
	}
	seen := map[string]struct{}{}
	objectDigests := map[string]struct{}{}
	for _, reference := range entry.Objects {
		if _, duplicate := seen[reference.Name]; duplicate {
			return fmt.Errorf("duplicate corpus object reference %s", reference.Name)
		}
		seen[reference.Name] = struct{}{}
		if _, err := store.ReadObject(reference); err != nil {
			return fmt.Errorf("verify corpus object %s: %w", reference.Name, err)
		}
		objectDigests[reference.Digest] = struct{}{}
	}
	seenAttempts := map[string]struct{}{}
	for _, attempt := range entry.Attempts {
		if attempt.ID == "" || attempt.Kind == "" || attempt.NetworkUID == "" ||
			attempt.RunUID == "" || !digestPattern.MatchString(attempt.ScheduleDigest) ||
			!digestPattern.MatchString(attempt.EvidenceDigest) {
			return errors.New("corpus attempt is incomplete")
		}
		switch attempt.Kind {
		case "Source", "Confirmation", "Reduction":
		default:
			return fmt.Errorf("corpus attempt %s has unsupported kind %s", attempt.ID, attempt.Kind)
		}
		if _, duplicate := seenAttempts[attempt.ID]; duplicate {
			return fmt.Errorf("duplicate corpus attempt %s", attempt.ID)
		}
		seenAttempts[attempt.ID] = struct{}{}
		if _, retained := objectDigests[attempt.EvidenceDigest]; !retained {
			return fmt.Errorf("corpus attempt %s evidence is not retained", attempt.ID)
		}
	}
	if len(entry.Advisories) > 256 {
		return errors.New("corpus advisory references exceed bound")
	}
	for _, advisory := range entry.Advisories {
		if _, found := objectDigests[advisory.ObjectDigest]; !found ||
			advisory.DecisionDomain == "" || len(advisory.DecisionDomain) > 256 ||
			!digestPattern.MatchString(advisory.ReceiptDigest) {
			return errors.New("corpus advisory does not bind a retained object and decision receipt")
		}
	}
	if len(entry.Reduction) > 1024 {
		return errors.New("corpus reduction inventory exceeds bound")
	}
	seenReduction := map[string]struct{}{}
	for _, digest := range entry.Reduction {
		if _, found := objectDigests[digest]; !found {
			return errors.New("corpus reduction graph is not retained in the object inventory")
		}
		if _, duplicate := seenReduction[digest]; duplicate {
			return errors.New("corpus reduction inventory contains a duplicate")
		}
		seenReduction[digest] = struct{}{}
	}
	return nil
}

// Entries lists every verified manifest in stable fingerprint/digest order.
func (store *Store) Entries() ([]Entry, error) {
	result := []Entry{}
	root := filepath.Join(store.root, "entries")
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return fmt.Errorf("unexpected corpus entry file %s", path)
		}
		entry, err := store.readEntry(path)
		if err != nil {
			return err
		}
		result = append(result, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Fingerprint == result[j].Fingerprint {
			return result[i].Digest < result[j].Digest
		}
		return result[i].Fingerprint < result[j].Fingerprint
	})
	return result, nil
}

// EntriesForFingerprint returns all immutable observations of one semantic
// outcome. A fingerprint can intentionally have multiple entry manifests.
func (store *Store) EntriesForFingerprint(fingerprint string) ([]Entry, error) {
	if !digestPattern.MatchString(fingerprint) {
		return nil, errors.New("semantic fingerprint must be SHA-256")
	}
	root := filepath.Join(store.root, "entries", strings.TrimPrefix(fingerprint, "sha256:"))
	items, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := make([]Entry, 0, len(items))
	for _, item := range items {
		if item.IsDir() || filepath.Ext(item.Name()) != ".json" {
			return nil, fmt.Errorf("unexpected corpus entry file %s", item.Name())
		}
		entry, err := store.readEntry(filepath.Join(root, item.Name()))
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Digest < result[j].Digest })
	return result, nil
}

// Verify checks the complete permanent corpus tree, including unreferenced
// objects and session-journal artifact bindings.
func (store *Store) Verify() (Verification, error) {
	result := Verification{SchemaVersion: "stacks-attacknet-corpus-verification/v1", Valid: true}
	usage, err := store.corpusUsage("")
	if err != nil {
		result.Valid = false
		return result, err
	}
	result.Bytes = usage
	if usage > store.maximumBytes {
		result.Valid = false
		return result, errors.New("verified corpus exceeds configured maximum bytes")
	}
	if err := store.verifyRootLayout(); err != nil {
		result.Valid = false
		return result, err
	}
	objects, err := store.verifyObjectTree()
	if err != nil {
		result.Valid = false
		return result, err
	}
	result.Objects = len(objects)
	if err := store.verifyEntries(&result); err != nil {
		result.Valid = false
		return result, err
	}
	if err := store.verifySessions(); err != nil {
		result.Valid = false
		return result, err
	}
	if err := store.verifyReports(); err != nil {
		result.Valid = false
		return result, err
	}
	if err := store.verifyAudit(&result); err != nil {
		result.Valid = false
		return result, err
	}
	return result, nil
}

// verifyRootLayout validates corpus metadata and top-level paths.
func (store *Store) verifyRootLayout() error {
	data, err := readRegularFile(filepath.Join(store.root, "corpus.json"), maximumMetadataBytes)
	if err != nil {
		return fmt.Errorf("verify corpus metadata: %w", err)
	}
	if !validMetadata(data, store.maximumBytes) {
		return errors.New("corpus metadata is invalid")
	}
	allowedDirectories := map[string]struct{}{
		"objects": {}, "entries": {}, "sessions": {}, "reports": {}, "audit": {}, ".pending": {},
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, allowed := allowedDirectories[entry.Name()]; allowed && entry.IsDir() {
			continue
		}
		if entry.Name() == "corpus.json" && !entry.IsDir() {
			continue
		}
		if entry.Name() == ".writer.lock" && !entry.IsDir() {
			if _, err := store.LockRecord(); err != nil {
				return fmt.Errorf("verify corpus writer lock: %w", err)
			}
			continue
		}
		return fmt.Errorf("unexpected corpus root entry %s", entry.Name())
	}
	pending, err := os.ReadDir(filepath.Join(store.root, ".pending"))
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("corpus contains an unrecovered pending write")
	}
	return nil
}

// verifyObjectTree authenticates every stored object, including orphans.
func (store *Store) verifyObjectTree() (map[string]int64, error) {
	objectRoot := filepath.Join(store.root, "objects")
	children, err := os.ReadDir(objectRoot)
	if err != nil {
		return nil, err
	}
	if len(children) != 1 || children[0].Name() != "sha256" || !children[0].IsDir() {
		return nil, errors.New("corpus object store has an invalid layout")
	}
	root := filepath.Join(store.root, "objects", "sha256")
	objects := map[string]int64{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if entry.IsDir() {
			if len(parts) != 1 || !digestPrefixPattern.MatchString(parts[0]) {
				return fmt.Errorf("unexpected object directory %s", path)
			}
			return nil
		}
		if len(parts) != 2 || len(parts[0]) != 2 || parts[0] != firstDigestBytes(parts[1]) ||
			!digestPattern.MatchString("sha256:"+parts[1]) {
			return fmt.Errorf("object is stored under the wrong identity: %s", path)
		}
		data, err := readRegularFile(path, store.maximumBytes)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if digest != "sha256:"+parts[1] {
			return fmt.Errorf("object %s digest mismatch", path)
		}
		objects[digest] = int64(len(data))
		return nil
	})
	return objects, err
}

// firstDigestBytes returns the object-store shard prefix of a digest value.
func firstDigestBytes(value string) string {
	if len(value) < 2 {
		return ""
	}
	return value[:2]
}

// verifyEntries validates every stored semantic manifest.
func (store *Store) verifyEntries(result *Verification) error {
	root := filepath.Join(store.root, "entries")
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if entry.IsDir() {
			if len(parts) != 1 || !digestPattern.MatchString("sha256:"+parts[0]) {
				return fmt.Errorf("unexpected corpus entry directory %s", path)
			}
			return nil
		}
		if len(parts) != 2 || filepath.Ext(path) != ".json" {
			return fmt.Errorf("unexpected corpus entry file %s", path)
		}
		if _, err := store.readEntry(path); err != nil {
			return fmt.Errorf("verify corpus entry %s: %w", path, err)
		}
		result.Entries++
		return nil
	})
}

// verifySessions validates every journal chain and referenced artifact.
func (store *Store) verifySessions() error {
	root := filepath.Join(store.root, "sessions")
	sessions, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if !session.IsDir() || !digestPattern.MatchString("sha256:"+session.Name()) {
			return fmt.Errorf("unexpected corpus session entry %s", session.Name())
		}
		sessionRoot := filepath.Join(root, session.Name())
		children, err := os.ReadDir(sessionRoot)
		if err != nil {
			return err
		}
		if len(children) != 1 || children[0].Name() != "journal" || !children[0].IsDir() {
			return fmt.Errorf("session %s has an invalid layout", session.Name())
		}
		journal, err := store.OpenJournal("sha256:" + session.Name())
		if err != nil {
			return fmt.Errorf("verify session %s: %w", session.Name(), err)
		}
		for _, record := range journal.Records() {
			for _, reference := range record.Artifacts {
				if _, err := store.ReadObject(reference); err != nil {
					return fmt.Errorf("session %s record %d artifact %s: %w", session.Name(), record.Sequence, reference.Name, err)
				}
			}
		}
	}
	return nil
}

// verifyReports validates every immutable session report pointer.
func (store *Store) verifyReports() error {
	root := filepath.Join(store.root, "reports")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		base := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" ||
			!digestPattern.MatchString("sha256:"+base) {
			return fmt.Errorf("unexpected corpus report file %s", entry.Name())
		}
		if _, err := store.Report("sha256:" + base); err != nil {
			return fmt.Errorf("verify corpus report %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// verifyAudit validates every administrative audit pointer.
func (store *Store) verifyAudit(result *Verification) error {
	root := filepath.Join(store.root, "audit")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		data, err := readRegularFile(path, maximumMetadataBytes)
		if err != nil {
			return err
		}
		var pointer AuditPointer
		if entry.IsDir() || filepath.Ext(path) != ".json" || json.Unmarshal(data, &pointer) != nil ||
			pointer.SchemaVersion != AuditPointerSchema || !auditKindPattern.MatchString(pointer.Kind) ||
			entry.Name() != pointer.Kind+"-"+strings.TrimPrefix(pointer.Record.Digest, "sha256:")+".json" {
			return fmt.Errorf("invalid corpus audit pointer %s", path)
		}
		if _, err := store.ReadObject(pointer.Record); err != nil {
			return err
		}
		result.AuditRecords++
	}
	return nil
}

func (store *Store) objectPath(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", errors.New("object digest must be SHA-256")
	}
	value := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(store.root, "objects", "sha256", value[:2], value), nil
}

func (store *Store) readEntry(path string) (Entry, error) {
	data, err := readRegularFile(path, maximumMetadataBytes)
	if err != nil {
		return Entry{}, err
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return Entry{}, fmt.Errorf("decode corpus entry: %w", err)
	}
	view := entry
	view.Digest = ""
	digest, err := canonical.Digest(view)
	if err != nil || digest != entry.Digest {
		return Entry{}, errors.New("corpus entry digest mismatch")
	}
	if !digestPattern.MatchString(entry.Fingerprint) ||
		filepath.Base(filepath.Dir(path)) != strings.TrimPrefix(entry.Fingerprint, "sha256:") ||
		filepath.Base(path) != strings.TrimPrefix(entry.Digest, "sha256:")+".json" {
		return Entry{}, errors.New("corpus entry is stored under the wrong identity")
	}
	if err := store.validateEntry(entry); err != nil {
		return Entry{}, fmt.Errorf("validate corpus entry: %w", err)
	}
	return entry, nil
}

// validateObjectReference checks the bounded immutable object envelope.
func validateObjectReference(reference ObjectReference) error {
	if reference.Name == "" || len(reference.Name) > 256 ||
		!digestPattern.MatchString(reference.Digest) || reference.Size < 0 ||
		reference.Size > 1<<50 || len(reference.ContentType) > 256 {
		return errors.New("object reference is incomplete or unbounded")
	}
	return nil
}

func (store *Store) writeCanonical(path string, value any, exclusive bool) error {
	data, err := canonical.Marshal(value)
	if err != nil {
		return err
	}
	return store.writeBytes(path, append(data, '\n'), exclusive)
}

func (store *Store) writeBytes(path string, data []byte, exclusive bool) error {
	store.writeMu.Lock()
	defer store.writeMu.Unlock()
	if int64(len(data)) > store.maximumBytes {
		return errors.New("artifact exceeds corpus maximum bytes")
	}
	currentSize := int64(0)
	if current, err := readRegularFile(path, store.maximumBytes); err == nil {
		if bytes.Equal(current, data) {
			return nil
		}
		currentSize = int64(len(current))
		if exclusive {
			return fmt.Errorf("refusing to replace immutable corpus path %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	usage, err := store.corpusUsage(path)
	if err != nil {
		return err
	}
	if usage-currentSize+int64(len(data)) > store.maximumBytes {
		return errors.New("corpus write would exceed configured maximum bytes")
	}
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(filepath.Join(store.root, ".pending"), ".attacknet-corpus-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if exclusive {
		if err := os.Link(temporaryPath, path); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			current, readErr := readRegularFile(path, store.maximumBytes)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(current, data) {
				return fmt.Errorf("refusing to replace immutable corpus path %s", path)
			}
		}
	} else if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

// corpusUsage returns the bytes occupied by every permanent regular file.
// The writer lock is transient serialization state and is deliberately not
// charged to the retained corpus budget.
func (store *Store) corpusUsage(replacedPath string) (int64, error) {
	total := int64(0)
	pendingRoot := filepath.Join(store.root, ".pending")
	err := filepath.WalkDir(store.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == pendingRoot && entry.IsDir() {
			return filepath.SkipDir
		}
		if path == filepath.Join(store.root, ".writer.lock") || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("corpus contains a non-regular file: %s", path)
		}
		if path == replacedPath {
			total += info.Size()
			return nil
		}
		if info.Size() > store.maximumBytes-total {
			return errors.New("corpus exceeds configured maximum bytes")
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// recoverPendingWrites removes only unpublished private temporaries while the
// caller owns the corpus writer lock. Permanent paths are never inferred from
// or replaced by these bytes; the interrupted operation is replayed instead.
func (store *Store) recoverPendingWrites() error {
	root := filepath.Join(store.root, ".pending")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !pendingWritePattern.MatchString(entry.Name()) {
			return fmt.Errorf("unexpected pending corpus entry %s", entry.Name())
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pending corpus entry is not a regular file: %s", entry.Name())
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return syncDirectory(root)
}

// syncDirectory durably records directory-entry mutations.
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("path is not a regular non-symlink file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds read limit: %s", path)
	}
	return data, nil
}

func sortedUnique(value []string) ([]string, error) {
	result := append([]string(nil), value...)
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, fmt.Errorf("duplicate value %q", result[index])
		}
	}
	return result, nil
}
