package burnchain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Status is the clock's latest local observation.
type Status struct {
	// State is starting, running, paused, degraded, or stopped.
	State string `json:"state"`
	// BitcoinHeight is the last observed canonical height.
	BitcoinHeight *uint64 `json:"bitcoinHeight,omitempty"`
	// ChainInfo identifies the currently selected Bitcoin branch.
	ChainInfo *ChainInfo `json:"chainInfo,omitempty"`
	// ChainTips contains the bounded locally-known Bitcoin branch set.
	ChainTips []ChainTip `json:"chainTips,omitempty"`
	// Peers contains the bounded currently-connected Bitcoin peer set.
	Peers []PeerInfo `json:"peers,omitempty"`
	// ObservationError explains why branch evidence is unavailable.
	ObservationError string `json:"observationError,omitempty"`
	// PolicyGeneration is the last applied immutable generation.
	PolicyGeneration *uint64 `json:"policyGeneration,omitempty"`
	// PolicyMode is the currently applied continuous-mining mode.
	PolicyMode Mode `json:"policyMode,omitempty"`
	// IntervalSeconds is the requested base cadence.
	IntervalSeconds *uint64 `json:"intervalSeconds,omitempty"`
	// AddressMode is the currently applied destination-selection mode.
	AddressMode AddressMode `json:"addressMode,omitempty"`
	// Detail is a bounded machine-readable diagnostic.
	Detail string `json:"detail,omitempty"`
	// LastSuccessAt is the latest successful Bitcoin height observation.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	// UpdatedAt is the observation wall-clock time.
	UpdatedAt time.Time `json:"updatedAt"`
}

// StatusRecorder retains the latest status while delegating durable persistence.
type StatusRecorder struct {
	Delegate StatusSink

	mutex    sync.RWMutex
	status   Status
	observed bool
}

// Write records the observation before forwarding it to the optional delegate.
func (recorder *StatusRecorder) Write(status Status) error {
	recorder.mutex.Lock()
	if status.ObservationError == "" && (status.ChainInfo != nil || (status.State == "running" && status.BitcoinHeight != nil)) {
		succeeded := status.UpdatedAt
		status.LastSuccessAt = &succeeded
	} else if recorder.status.LastSuccessAt != nil {
		succeeded := *recorder.status.LastSuccessAt
		status.LastSuccessAt = &succeeded
	}
	recorder.status = status
	recorder.observed = true
	recorder.mutex.Unlock()
	if recorder.Delegate != nil {
		return recorder.Delegate.Write(status)
	}
	return nil
}

// Snapshot returns the latest complete observation.
func (recorder *StatusRecorder) Snapshot() (Status, bool) {
	recorder.mutex.RLock()
	defer recorder.mutex.RUnlock()
	return recorder.status, recorder.observed
}

// StatusSink persists clock observations.
type StatusSink interface {
	Write(Status) error
}

// FileStatusSink atomically writes the compatibility status projection.
type FileStatusSink struct {
	// Path is the atomically replaced status projection.
	Path string
}

// Write replaces the status projection atomically in its destination directory.
func (sink FileStatusSink) Write(status Status) error {
	directory := filepath.Dir(sink.Path)
	file, err := os.CreateTemp(directory, ".burnchain-status-*")
	if err != nil {
		return fmt.Errorf("create status file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return fmt.Errorf("set status permissions: %w", err)
	}
	height := "unknown"
	if status.BitcoinHeight != nil {
		height = fmt.Sprint(*status.BitcoinHeight)
	}
	generation := "unknown"
	if status.PolicyGeneration != nil {
		generation = fmt.Sprint(*status.PolicyGeneration)
	}
	detail := strings.NewReplacer("\n", "-", "\r", "-").Replace(status.Detail)
	updated := status.UpdatedAt
	if updated.IsZero() {
		updated = time.Now()
	}
	_, writeErr := fmt.Fprintf(file, "state=%s\nbitcoin_height=%s\npolicy_generation=%s\ndetail=%s\nupdated_at=%d\n",
		status.State, height, generation, detail, updated.Unix())
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("write status: %w", writeErr)
	}
	if err := os.Rename(temporary, sink.Path); err != nil {
		return fmt.Errorf("replace status: %w", err)
	}
	return nil
}
