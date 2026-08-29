// Package protocolobservation acquires and evaluates identity-bound protocol
// observations for Attacknet controllers.
package protocolobservation

import (
	"fmt"
	"sort"
	"time"

	dto "github.com/prometheus/client_model/go"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const (
	// EvidenceActorSelfReported identifies protocol values exported by an actor
	// and collected through an orchestrator-verified endpoint.
	EvidenceActorSelfReported = "actor_self_reported"
	// EvidenceOrchestratorObserved identifies Kubernetes and controller state.
	EvidenceOrchestratorObserved = "orchestrator_observed"
	// UnavailableIdentity records that the controller could not establish one
	// stable admitted-identity window for protocol collection.
	UnavailableIdentity = "IdentityUnavailable"
)

// Source identifies the immutable actor and collection boundary for one metric
// family.
type Source struct {
	Actor          string    `json:"actor"`
	Role           string    `json:"role"`
	PodName        string    `json:"podName"`
	PodUID         string    `json:"podUID"`
	RuntimeImageID string    `json:"runtimeImageID"`
	ServiceName    string    `json:"serviceName"`
	ObservedAt     time.Time `json:"observedAt"`
	EvidenceClass  string    `json:"evidenceClass"`
}

// ActorSnapshot contains one actor's bounded Prometheus metric families.
type ActorSnapshot struct {
	Source          Source
	Families        map[string]*dto.MetricFamily
	ChainView       *StacksChainView
	ChainObservedAt time.Time
	ChainError      string
	Error           string
}

// StacksChainView is the bounded /v2/info identity for one Stacks actor.
type StacksChainView struct {
	BurnBlockHeight     uint64 `json:"burnBlockHeight"`
	BurnConsensusHash   string `json:"burnConsensusHash"`
	StacksTipHeight     uint64 `json:"stacksTipHeight"`
	StacksTip           string `json:"stacksTip"`
	StacksConsensusHash string `json:"stacksConsensusHash"`
	FullySynced         bool   `json:"fullySynced"`
}

// BitcoinSnapshot is one identity-bound BurnchainPolicy observation.
type BitcoinSnapshot struct {
	Source         Source                                     `json:"source"`
	PolicyName     string                                     `json:"policyName"`
	TopologyDigest string                                     `json:"topologyDigest"`
	Height         int64                                      `json:"height"`
	Headers        int64                                      `json:"headers"`
	BestBlockHash  string                                     `json:"bestBlockHash"`
	Chainwork      string                                     `json:"chainwork"`
	ChainTips      []attacknetv1beta1.BurnchainChainTipStatus `json:"chainTips,omitempty"`
	Peers          []attacknetv1beta1.BurnchainPeerStatus     `json:"peers,omitempty"`
	Error          string                                     `json:"error,omitempty"`
}

// Snapshot is one inventory-bound cohort observation.
type Snapshot struct {
	NetworkUID        string
	InventoryDigest   string
	ObservedAt        time.Time
	Actors            []ActorSnapshot
	Bitcoin           []BitcoinSnapshot
	BurnchainTopology *attacknetv1beta1.AdmittedBurnchainTopology
	// UnavailableReason is a bounded controller-origin reason emitted when no
	// stable identity-bound snapshot could be collected.
	UnavailableReason string
}

// BitcoinActor returns one exact Bitcoin observation.
func (s Snapshot) BitcoinActor(name string) (BitcoinSnapshot, bool) {
	index := sort.Search(len(s.Bitcoin), func(index int) bool {
		return s.Bitcoin[index].Source.Actor >= name
	})
	if index >= len(s.Bitcoin) || s.Bitcoin[index].Source.Actor != name {
		return BitcoinSnapshot{}, false
	}
	return s.Bitcoin[index], true
}

// Actor returns one exact actor observation.
func (s Snapshot) Actor(name string) (ActorSnapshot, bool) {
	index := sort.Search(len(s.Actors), func(index int) bool {
		return s.Actors[index].Source.Actor >= name
	})
	if index >= len(s.Actors) || s.Actors[index].Source.Actor != name {
		return ActorSnapshot{}, false
	}
	return s.Actors[index], true
}

// Complete reports whether every expected metrics endpoint was collected.
func (s Snapshot) Complete() bool {
	if len(s.Actors) == 0 {
		return false
	}
	for _, actor := range s.Actors {
		if actor.Error != "" {
			return false
		}
	}
	return true
}

// Scalar returns the only unlabeled gauge, counter, or untyped value in a
// family. Multiple or labeled samples are rejected rather than guessed.
func (a ActorSnapshot) Scalar(name string) (float64, error) {
	if a.Error != "" {
		return 0, fmt.Errorf("actor %s metrics unavailable: %s", a.Source.Actor, a.Error)
	}
	family := a.Families[name]
	if family == nil {
		return 0, fmt.Errorf("actor %s metric %s is absent", a.Source.Actor, name)
	}
	if len(family.Metric) != 1 || len(family.Metric[0].Label) != 0 {
		return 0, fmt.Errorf("actor %s metric %s is not one unlabeled sample", a.Source.Actor, name)
	}
	metric := family.Metric[0]
	switch family.GetType() {
	case dto.MetricType_GAUGE:
		return metric.GetGauge().GetValue(), nil
	case dto.MetricType_COUNTER:
		return metric.GetCounter().GetValue(), nil
	case dto.MetricType_UNTYPED:
		return metric.GetUntyped().GetValue(), nil
	default:
		return 0, fmt.Errorf("actor %s metric %s has unsupported scalar type %s", a.Source.Actor, name, family.GetType())
	}
}

// Sum returns the sum of scalar counter or gauge samples matching every
// requested label.
func (a ActorSnapshot) Sum(name string, labels map[string]string) (float64, error) {
	if a.Error != "" {
		return 0, fmt.Errorf("actor %s metrics unavailable: %s", a.Source.Actor, a.Error)
	}
	family := a.Families[name]
	if family == nil {
		return 0, fmt.Errorf("actor %s metric %s is absent", a.Source.Actor, name)
	}
	total := 0.0
	matched := 0
	for _, metric := range family.Metric {
		if !labelsMatch(metric, labels) {
			continue
		}
		switch family.GetType() {
		case dto.MetricType_GAUGE:
			total += metric.GetGauge().GetValue()
		case dto.MetricType_COUNTER:
			total += metric.GetCounter().GetValue()
		default:
			return 0, fmt.Errorf("actor %s metric %s has unsupported sum type %s", a.Source.Actor, name, family.GetType())
		}
		matched++
	}
	if matched == 0 {
		return 0, fmt.Errorf("actor %s metric %s has no matching samples", a.Source.Actor, name)
	}
	return total, nil
}

func labelsMatch(metric *dto.Metric, expected map[string]string) bool {
	if len(expected) == 0 {
		return true
	}
	labels := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		labels[pair.GetName()] = pair.GetValue()
	}
	for name, value := range expected {
		if labels[name] != value {
			return false
		}
	}
	return true
}
