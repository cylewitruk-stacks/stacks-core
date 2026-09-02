// Package fuzzsession coordinates finite fuzz trials through existing
// Attacknet APIs. It never mutates actor workloads or fault backends directly.
package fuzzsession

import (
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
)

const (
	// CapacitySchema identifies one capacity-admission receipt.
	CapacitySchema = "stacks-attacknet-fuzz-capacity/v1"
	// SessionReportSchema identifies one static session report.
	SessionReportSchema = "stacks-attacknet-fuzz-session-report/v1"
)

// NodeCapacity contains trusted kubelet filesystem observations.
type NodeCapacity struct {
	Name                string `json:"name"`
	RootAvailableBytes  int64  `json:"rootAvailableBytes"`
	ImageAvailableBytes int64  `json:"imageAvailableBytes"`
}

// CapacitySnapshot is the finite input to capacity admission.
type CapacitySnapshot struct {
	Nodes                []NodeCapacity `json:"nodes"`
	CorpusAvailableBytes int64          `json:"corpusAvailableBytes"`
	ObservedAt           time.Time      `json:"observedAt"`
}

// CapacityReceipt records a fail-closed capacity decision.
type CapacityReceipt struct {
	SchemaVersion string                `json:"schemaVersion"`
	Policy        fuzzplan.CapacityPlan `json:"policy"`
	Snapshot      CapacitySnapshot      `json:"snapshot"`
	Admitted      bool                  `json:"admitted"`
	Reason        string                `json:"reason,omitempty"`
	Digest        string                `json:"digest"`
}

// TrialResult is the trusted bounded outcome consumed by classification.
type TrialResult struct {
	Phase                string   `json:"phase"`
	Reason               string   `json:"reason"`
	Attribution          string   `json:"attribution"`
	ViolatedAssertions   []string `json:"violatedAssertions,omitempty"`
	MechanismFamilies    []string `json:"mechanismFamilies,omitempty"`
	IdentityDivergence   string   `json:"identityDivergence,omitempty"`
	VersionCohortDigest  string   `json:"versionCohortDigest,omitempty"`
	EvidenceComplete     bool     `json:"evidenceComplete"`
	IncidentBundleSealed bool     `json:"incidentBundleSealed"`
	LokiExportComplete   bool     `json:"lokiExportComplete"`
}

// Classification is the session-level interpretation of one controller run.
type Classification struct {
	Class       string `json:"class"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason"`
}
