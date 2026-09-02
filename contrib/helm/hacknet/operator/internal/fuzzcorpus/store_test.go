package fuzzcorpus

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

func TestStoreRoundTripAndSemanticDeduplication(t *testing.T) {
	store := openTestStore(t)
	object, err := store.PutObject("run-status", "application/json", []byte("status"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := SemanticFingerprint(FingerprintInput{
		SchemaVersion: FingerprintSchema,
		Phase:         "Failed", Reason: "ProtocolDuringViolated", Attribution: "ProtocolAssertion",
		AssertionResults:  []string{"b:Violated", "a:Proven"},
		MechanismFamilies: []string{"NetworkChaos", "PodChaos"},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := store.PutEntry(Entry{
		SchemaVersion: EntrySchema, Fingerprint: fingerprint,
		Classification: "NetworkFailureCandidate",
		SessionDigest:  strings.Repeat("sha256:a", 1) + strings.Repeat("a", 63),
		TrialOrdinal:   1, SourceRun: "run-1",
		ReplayCommand: []string{"attacknet", "corpus", "replay", fingerprint},
		Objects:       []ObjectReference{object},
		Attempts: []Attempt{{
			ID: "source", Kind: "Source", NetworkUID: "network-uid", RunUID: "run-uid",
			ScheduleDigest: strings.Repeat("sha256:b", 1) + strings.Repeat("b", 63),
			Classification: "NetworkFailureCandidate", EvidenceDigest: object.Digest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.PutEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Digest != entry.Digest {
		t.Fatalf("entry digest changed: %s != %s", repeated.Digest, entry.Digest)
	}
	verification, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.Entries != 1 || verification.Objects != 1 ||
		verification.Bytes <= int64(len("status")) {
		t.Fatalf("unexpected verification: %+v", verification)
	}
}

func TestStoreDistinguishesExplicitEmptyEvidenceFromMissingBytes(t *testing.T) {
	store := openTestStore(t)
	reference, err := store.PutObject("empty.log", "text/plain", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	const emptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if reference.Size != 0 || reference.Digest != emptyDigest {
		t.Fatalf("empty evidence reference = %#v", reference)
	}
	data, err := store.ReadObject(reference)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty evidence round trip = %q, %v", data, err)
	}
	if _, err := store.PutObject("missing.log", "text/plain", nil); err == nil {
		t.Fatal("missing object bytes were accepted as explicit empty evidence")
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid || verification.Objects != 1 {
		t.Fatalf("empty evidence verification = %#v, %v", verification, err)
	}
}

func TestOpenConcurrentlyPublishesOneQuotaBoundMetadataRecord(t *testing.T) {
	root := t.TempDir()
	const workers = 16
	errorsByWorker := make([]error, workers)
	var group sync.WaitGroup
	for worker := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			now := func() time.Time {
				return time.Date(2026, 8, 31, 12, 0, worker, 0, time.UTC)
			}
			_, errorsByWorker[worker] = Open(root, 1<<20, now)
		}()
	}
	group.Wait()
	for worker, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("initializer %d failed: %v", worker, err)
		}
	}
	store, err := OpenExisting(root, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid || verification.Bytes < 1 || verification.Bytes > 1<<20 {
		t.Fatalf("concurrently initialized corpus = %#v, %v", verification, err)
	}
}

func TestSemanticFingerprintRejectsDuplicateDimensions(t *testing.T) {
	_, err := SemanticFingerprint(FingerprintInput{
		SchemaVersion: FingerprintSchema,
		Phase:         "Failed", Reason: "reason", Attribution: "source",
		AssertionResults: []string{"same", "same"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}

func TestSessionReportPointerBindsImmutableObject(t *testing.T) {
	store := openTestStore(t)
	session := "sha256:" + strings.Repeat("a", 64)
	reference, err := store.PutCanonicalObject("session-report", "application/json", map[string]any{
		"schemaVersion": "report/v1", "sessionDigest": session,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutReportPointer(session, reference); err != nil {
		t.Fatal(err)
	}
	pointer, err := store.Report(session)
	if err != nil || pointer.Report.Digest != reference.Digest {
		t.Fatalf("report pointer = %#v, %v", pointer, err)
	}
	other, err := store.PutObject("other-report", "application/json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutReportPointer(session, other); err == nil {
		t.Fatal("immutable report pointer was replaced")
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid || verification.Objects != 2 {
		t.Fatalf("report verification = %#v, %v", verification, err)
	}
}

func TestPutObjectEnforcesAggregateCorpusByteBound(t *testing.T) {
	root := t.TempDir()
	const maximumBytes = int64(512)
	store, err := Open(root, maximumBytes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := store.corpusUsage("")
	if err != nil {
		t.Fatal(err)
	}
	size := int((maximumBytes-usage)/2 + 1)
	if _, err := store.PutObject("first", "application/octet-stream", bytes.Repeat([]byte{'a'}, size)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutObject("second", "application/octet-stream", bytes.Repeat([]byte{'b'}, size)); err == nil ||
		!strings.Contains(err.Error(), "exceed configured maximum") {
		t.Fatalf("expected aggregate corpus bound rejection, got %v", err)
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid || verification.Objects != 1 || verification.Bytes > maximumBytes {
		t.Fatalf("verification after bounded rejection = %#v, %v", verification, err)
	}
}

func TestVerifyIncludesAndAuthenticatesOrphanObjects(t *testing.T) {
	store := openTestStore(t)
	reference, err := store.PutObject("orphan", "application/octet-stream", []byte("orphan"))
	if err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify()
	if err != nil || verification.Objects != 1 {
		t.Fatalf("orphan object was not verified: %#v, %v", verification, err)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected orphan corruption rejection, got %v", err)
	}
}

func TestReadEntryReappliesSemanticInvariants(t *testing.T) {
	store := openTestStore(t)
	object, err := store.PutObject("evidence", "application/json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	entry, err := store.PutEntry(Entry{
		SchemaVersion: EntrySchema, Fingerprint: fingerprint, Classification: "Clean",
		SessionDigest: "sha256:" + strings.Repeat("b", 64), TrialOrdinal: 1,
		SourceRun: "run", ReplayCommand: []string{"attacknet", "corpus", "replay", fingerprint},
		Objects: []ObjectReference{object}, Attempts: []Attempt{{
			ID: "source", Kind: "Source", NetworkUID: "network", RunUID: "run",
			ScheduleDigest: "sha256:" + strings.Repeat("c", 64),
			Classification: "Clean", EvidenceDigest: object.Digest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry.Classification = "FabricatedSuccess"
	entry.Digest = ""
	digest, err := canonical.Digest(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Digest = digest
	path := filepath.Join(store.root, "entries", strings.TrimPrefix(fingerprint, "sha256:"), strings.TrimPrefix(digest, "sha256:")+".json")
	if err := store.writeCanonical(path, entry, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err == nil || !strings.Contains(err.Error(), "classification is unsupported") {
		t.Fatalf("expected resealed invalid entry rejection, got %v", err)
	}
}

func TestObjectIsImmutableAndCorruptionIsDetected(t *testing.T) {
	store := openTestStore(t)
	reference, err := store.PutObject("artifact", "text/plain", []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("substituted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadObject(reference); err == nil {
		t.Fatal("expected substituted object to be rejected")
	}
	if _, err := store.PutObject("artifact", "text/plain", []byte("original")); err == nil {
		t.Fatal("expected immutable path corruption to be rejected")
	}
}

func TestReadObjectRejectsSymlink(t *testing.T) {
	store := openTestStore(t)
	data := []byte("target")
	reference, err := store.PutObject("target", "text/plain", data)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadObject(reference); err == nil ||
		!strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestCorpusLockRequiresExactOwnerAndExplicitBreak(t *testing.T) {
	store := openTestStore(t)
	lock, err := store.AcquireLock("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLock("session-b"); err == nil {
		t.Fatal("expected second writer rejection")
	}
	wrong := lock.record
	wrong.Owner = "session-b"
	if err := store.BreakLock(wrong, "operator approved"); err == nil {
		t.Fatal("expected stale identity mismatch")
	}
	if err := store.BreakLock(lock.record, "operator approved"); err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify()
	if err != nil || !verification.Valid || verification.AuditRecords != 1 {
		t.Fatalf("expected one verified break receipt, got %#v: %v", verification, err)
	}
	if err := lock.Release(); err == nil {
		t.Fatal("expected broken lock release to fail")
	}
	replacement, err := store.AcquireLock("session-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestCorpusLockPublishesOneCompleteImmutableRecord(t *testing.T) {
	store := openTestStore(t)
	lock, err := store.AcquireLock("session-a")
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonical.Marshal(lock.record)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readRegularFile(filepath.Join(store.root, ".writer.lock"), maximumMetadataBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, append(want, '\n')) {
		t.Fatalf("published lock is not the complete canonical record: %q", data)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".attacknet-corpus-lock-") {
			t.Fatalf("lock temporary leaked into corpus: %s", entry.Name())
		}
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	partial := []byte(`{"schemaVersion":"stacks-attacknet-corpus-lock/v1"`)
	path := filepath.Join(store.root, ".writer.lock")
	if err := os.WriteFile(path, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLock("session-b"); err == nil {
		t.Fatal("expected an existing lock path to reject acquisition")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, partial) {
		t.Fatal("failed acquisition replaced the existing lock bytes")
	}
}

func TestCorpusLockRecoversOnlyPrivatePendingWrites(t *testing.T) {
	store := openTestStore(t)
	pendingRoot := filepath.Join(store.root, ".pending")
	pending := filepath.Join(pendingRoot, ".attacknet-corpus-12345")
	if err := os.WriteFile(pending, []byte("unpublished"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err == nil || !strings.Contains(err.Error(), "unrecovered pending write") {
		t.Fatalf("pending write was accepted by verification: %v", err)
	}
	lock, err := store.AcquireLock("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending write was not removed: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err != nil {
		t.Fatalf("recovered corpus does not verify: %v", err)
	}

	unexpected := filepath.Join(pendingRoot, "operator-note")
	if err := os.WriteFile(unexpected, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLock("session-b"); err == nil || !strings.Contains(err.Error(), "unexpected pending") {
		t.Fatalf("unexpected pending entry was removed or accepted: %v", err)
	}
	if _, err := os.Stat(unexpected); err != nil {
		t.Fatalf("unexpected pending entry was not preserved: %v", err)
	}
}

func TestJournalResumesVerifiedHashChainAndRejectsCorruption(t *testing.T) {
	store := openTestStore(t)
	session := "sha256:" + strings.Repeat("c", 64)
	journal, err := store.OpenOrCreateJournal(session)
	if err != nil {
		t.Fatal(err)
	}
	first, err := journal.Append(JournalRecord{Kind: "IntentCreateNetwork", Phase: "TrialPreparing", TrialOrdinal: 1, AttemptID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := journal.Append(JournalRecord{
		Kind: "ObservedNetwork", Phase: "TrialPreparing", TrialOrdinal: 1, AttemptID: "source",
		Resources: []ResourceIdentity{{APIVersion: "testing.stacks.org/v1beta1", Kind: "StacksNetwork", Namespace: "test", Name: "network", UID: "uid"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.PriorDigest != first.Digest {
		t.Fatal("journal does not bind its prior record")
	}
	reopened, err := store.OpenJournal(session)
	if err != nil || len(reopened.Records()) != 2 {
		t.Fatalf("resume failed: records=%d err=%v", len(reopened.Records()), err)
	}
	path := filepath.Join(reopened.root, fmt.Sprintf("%08d-%s.json", second.Sequence, strings.TrimPrefix(second.Digest, "sha256:")))
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenJournal(session); err == nil {
		t.Fatal("expected journal corruption rejection")
	}
	if _, err := store.Verify(); err == nil {
		t.Fatal("expected whole-corpus verification to reject journal corruption")
	}
}

func TestOpenJournalDoesNotCreateUnknownSession(t *testing.T) {
	store := openTestStore(t)
	session := "sha256:" + strings.Repeat("e", 64)
	sessionRoot := filepath.Join(store.Root(), "sessions", strings.TrimPrefix(session, "sha256:"))

	if _, err := store.OpenJournal(session); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opening an unknown session returned %v", err)
	}
	if _, err := os.Stat(sessionRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only open created an unknown session directory: %v", err)
	}
	if _, err := store.OpenOrCreateJournal(session); err != nil {
		t.Fatalf("explicit journal creation failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessionRoot, "journal")); err != nil {
		t.Fatalf("explicit journal creation did not create its directory: %v", err)
	}
}

func TestVerifyRejectsMissingJournalArtifact(t *testing.T) {
	store := openTestStore(t)
	reference, err := store.PutObject("descriptor", "application/json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	session := "sha256:" + strings.Repeat("d", 64)
	journal, err := store.OpenOrCreateJournal(session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(JournalRecord{
		Kind: "SessionPlanned", Phase: "Planned", Artifacts: []ObjectReference{reference},
	}); err != nil {
		t.Fatal(err)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err == nil || !strings.Contains(err.Error(), "record 1 artifact descriptor") {
		t.Fatalf("expected missing journal artifact rejection, got %v", err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	now := func() time.Time {
		return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	}
	store, err := Open(t.TempDir(), 1<<20, now)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
