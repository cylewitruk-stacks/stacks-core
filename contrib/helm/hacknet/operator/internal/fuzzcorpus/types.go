// Package fuzzcorpus stores immutable experiment artifacts and semantic
// classifications in a locally verifiable content-addressed corpus.
package fuzzcorpus

import "time"

const (
	// CorpusSchema identifies the corpus root metadata.
	CorpusSchema = "stacks-attacknet-fuzz-corpus/v1"
	// EntrySchema identifies one immutable semantic corpus entry.
	EntrySchema = "stacks-attacknet-fuzz-entry/v1"
	// FingerprintSchema identifies bounded semantic novelty inputs.
	FingerprintSchema = "stacks-attacknet-semantic-fingerprint/v1"
	// ReportPointerSchema identifies a stable session-to-report reference.
	ReportPointerSchema = "stacks-attacknet-fuzz-report-pointer/v1"
	// AuditPointerSchema identifies one immutable administrative audit record.
	AuditPointerSchema = "stacks-attacknet-fuzz-audit-pointer/v1"
)

// Metadata describes one initialized corpus.
type Metadata struct {
	SchemaVersion string    `json:"schemaVersion"`
	MaximumBytes  int64     `json:"maximumBytes"`
	CreatedAt     time.Time `json:"createdAt"`
}

// ObjectReference binds a logical artifact to immutable bytes.
type ObjectReference struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	ContentType string `json:"contentType,omitempty"`
}

// FingerprintInput contains only trusted bounded novelty dimensions.
type FingerprintInput struct {
	SchemaVersion       string   `json:"schemaVersion"`
	Phase               string   `json:"phase"`
	Reason              string   `json:"reason"`
	Attribution         string   `json:"attribution"`
	AssertionResults    []string `json:"assertionResults,omitempty"`
	MechanismFamilies   []string `json:"mechanismFamilies,omitempty"`
	IdentityDivergence  string   `json:"identityDivergence,omitempty"`
	VersionCohortDigest string   `json:"versionCohortDigest,omitempty"`
}

// Attempt records one source, confirmation, or reduction outcome.
type Attempt struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	NetworkUID     string `json:"networkUid"`
	RunUID         string `json:"runUid"`
	ScheduleDigest string `json:"scheduleDigest"`
	Classification string `json:"classification"`
	EvidenceDigest string `json:"evidenceDigest"`
}

// Entry is one immutable corpus classification and its artifact inventory.
type Entry struct {
	SchemaVersion  string              `json:"schemaVersion"`
	Fingerprint    string              `json:"fingerprint"`
	Classification string              `json:"classification"`
	SessionDigest  string              `json:"sessionDigest"`
	TrialOrdinal   int32               `json:"trialOrdinal"`
	SourceRun      string              `json:"sourceRun"`
	ReplayCommand  []string            `json:"replayCommand"`
	Objects        []ObjectReference   `json:"objects"`
	Attempts       []Attempt           `json:"attempts"`
	Advisories     []AdvisoryReference `json:"advisories,omitempty"`
	Reduction      []string            `json:"reduction,omitempty"`
	Digest         string              `json:"digest"`
}

// AdvisoryReference binds a retained ranking object to the decision receipt
// that consumed it.
type AdvisoryReference struct {
	ObjectDigest   string `json:"objectDigest"`
	DecisionDomain string `json:"decisionDomain"`
	ReceiptDigest  string `json:"receiptDigest"`
}

// Verification reports complete corpus integrity.
type Verification struct {
	SchemaVersion string `json:"schemaVersion"`
	Entries       int    `json:"entries"`
	Objects       int    `json:"objects"`
	AuditRecords  int    `json:"auditRecords"`
	Bytes         int64  `json:"bytes"`
	Valid         bool   `json:"valid"`
}

// ReportPointer makes one immutable report discoverable by session digest.
type ReportPointer struct {
	SchemaVersion string          `json:"schemaVersion"`
	SessionDigest string          `json:"sessionDigest"`
	Report        ObjectReference `json:"report"`
}

// AuditPointer makes one immutable administrative receipt discoverable.
type AuditPointer struct {
	SchemaVersion string          `json:"schemaVersion"`
	Kind          string          `json:"kind"`
	Record        ObjectReference `json:"record"`
}

// LockRecord identifies the one local writer.
type LockRecord struct {
	SchemaVersion string    `json:"schemaVersion"`
	Owner         string    `json:"owner"`
	ProcessID     int       `json:"processId"`
	AcquiredAt    time.Time `json:"acquiredAt"`
}

// ResourceIdentity binds a journal event to an exact Kubernetes object.
type ResourceIdentity struct {
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid,omitempty"`
	Generation      int64  `json:"generation,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// JournalRecord is one immutable, hash-chained session transition.
type JournalRecord struct {
	SchemaVersion string             `json:"schemaVersion"`
	Sequence      int64              `json:"sequence"`
	PriorDigest   string             `json:"priorDigest,omitempty"`
	Kind          string             `json:"kind"`
	Phase         string             `json:"phase"`
	TrialOrdinal  int32              `json:"trialOrdinal,omitempty"`
	AttemptID     string             `json:"attemptId,omitempty"`
	Resources     []ResourceIdentity `json:"resources,omitempty"`
	Artifacts     []ObjectReference  `json:"artifacts,omitempty"`
	OccurredAt    time.Time          `json:"occurredAt"`
	Digest        string             `json:"digest"`
}
