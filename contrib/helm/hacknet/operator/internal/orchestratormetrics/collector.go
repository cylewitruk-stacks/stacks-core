// Package orchestratormetrics exports bounded, controller-observed Attacknet state.
package orchestratormetrics

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

const evidenceSource = "orchestrator_observed"

// Collector reads cached controller state and exposes the finite Attacknet
// campaign/run metric contract used by dashboards and evidence collection.
type Collector struct {
	Reader client.Reader

	campaignInfo      *prometheus.Desc
	campaignTarget    *prometheus.Desc
	assertionOutcome  *prometheus.Desc
	runInfo           *prometheus.Desc
	budgetUsage       *prometheus.Desc
	minimization      *prometheus.Desc
	protocolAssertion *prometheus.Desc
	protocolSource    *prometheus.Desc
	protocolSourceAt  *prometheus.Desc
	collectionSuccess *prometheus.Desc
}

// NewCollector constructs an Attacknet orchestration collector.
func NewCollector(reader client.Reader) *Collector {
	return &Collector{
		Reader: reader,
		campaignInfo: prometheus.NewDesc("attacknet_fault_campaign_info", "Current orchestrator-observed FaultCampaign state.",
			[]string{"evidence_source", "network", "campaign", "type", "phase", "reason", "template"}, nil),
		campaignTarget: prometheus.NewDesc("attacknet_fault_campaign_target_info", "Exact actor targets admitted for a FaultCampaign.",
			[]string{"evidence_source", "network", "campaign", "actor", "role", "node"}, nil),
		assertionOutcome: prometheus.NewDesc("attacknet_fault_campaign_assertion_outcome", "Trusted effect and recovery assertion outcomes.",
			[]string{"evidence_source", "network", "campaign", "actor", "assertion", "outcome"}, nil),
		runInfo: prometheus.NewDesc("attacknet_run_info", "Current orchestrator-observed AttacknetRun state.",
			[]string{"evidence_source", "network", "run", "phase", "reason", "attribution", "replay", "minimization", "schedule_digest"}, nil),
		budgetUsage: prometheus.NewDesc("attacknet_run_budget_usage", "Current AttacknetRun budget consumption.",
			[]string{"evidence_source", "network", "run", "budget"}, nil),
		minimization: prometheus.NewDesc("attacknet_run_minimization_outcome", "Trusted terminal ddmin counterfactual classification.",
			[]string{"evidence_source", "network", "run", "attempt", "candidate_digest", "expected_assertion", "expected_status", "outcome", "reason", "evidence_digest", "causal_minimality_claimed"}, nil),
		protocolAssertion: prometheus.NewDesc("attacknet_run_protocol_assertion", "Identity-bound run protocol assertion outcome.",
			[]string{"evidence_source", "network", "run", "gate", "assertion", "type", "outcome", "reason"}, nil),
		protocolSource: prometheus.NewDesc("attacknet_run_protocol_assertion_source_info", "Exact admitted actor identity used by one protocol assertion observation.",
			[]string{"evidence_source", "network", "run", "gate", "assertion", "actor", "role", "pod", "pod_uid", "runtime_image_id", "service", "source_evidence_class"}, nil),
		protocolSourceAt: prometheus.NewDesc("attacknet_run_protocol_assertion_source_observed_timestamp_seconds", "Actor observation timestamp used by one protocol assertion.",
			[]string{"evidence_source", "network", "run", "gate", "assertion", "actor", "pod_uid"}, nil),
		collectionSuccess: prometheus.NewDesc("attacknet_orchestrator_metrics_collection_success", "Whether the latest orchestration state collection succeeded.", nil, nil),
	}
}

// Describe publishes every descriptor owned by the collector.
func (c *Collector) Describe(output chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{c.campaignInfo, c.campaignTarget, c.assertionOutcome, c.runInfo, c.budgetUsage, c.minimization, c.protocolAssertion, c.protocolSource, c.protocolSourceAt, c.collectionSuccess} {
		output <- descriptor
	}
}

// Collect lists campaign and run state from the manager cache for one scrape.
func (c *Collector) Collect(output chan<- prometheus.Metric) {
	if c.Reader == nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	campaigns := &attacknetv1beta1.FaultCampaignList{}
	runs := &attacknetv1beta1.AttacknetRunList{}
	if err := c.Reader.List(ctx, campaigns); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	if err := c.Reader.List(ctx, runs); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	success := true
	for index := range campaigns.Items {
		success = c.collectCampaign(output, &campaigns.Items[index]) && success
	}
	for index := range runs.Items {
		success = c.collectRun(output, &runs.Items[index]) && success
	}
	output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, boolFloat(success))
}

func (c *Collector) collectCampaign(output chan<- prometheus.Metric, campaign *attacknetv1beta1.FaultCampaign) bool {
	phase := campaign.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	output <- prometheus.MustNewConstMetric(c.campaignInfo, prometheus.GaugeValue, 1,
		evidenceSource, campaign.Spec.NetworkRef, campaign.Name, "multi-stage", phase,
		campaign.Status.Reason, strconv.FormatBool(campaign.Spec.Template))
	valid := true
	seenTargets := map[string]bool{}
	for _, stage := range campaign.Status.Stages {
		for _, action := range stage.Actions {
			for _, target := range action.ResolvedTargets {
				key := target.Actor + "\x00" + target.PodUID
				if seenTargets[key] {
					continue
				}
				seenTargets[key] = true
				output <- prometheus.MustNewConstMetric(c.campaignTarget, prometheus.GaugeValue, 1,
					evidenceSource, campaign.Spec.NetworkRef, campaign.Name, target.Actor, target.Role, target.Node)
			}
			valid = c.collectAssertionResults(output, campaign, action.EffectResults) && valid
			valid = c.collectAssertionResults(output, campaign, action.RecoveryResults) && valid
		}
		valid = c.collectAssertionResults(output, campaign, stage.EffectResults) && valid
		valid = c.collectAssertionResults(output, campaign, stage.RecoveryResults) && valid
	}
	return valid
}

func (c *Collector) collectAssertionResults(output chan<- prometheus.Metric, campaign *attacknetv1beta1.FaultCampaign, values []apixv1.JSON) bool {
	results, valid := decodeResults(values)
	for _, result := range results {
		output <- prometheus.MustNewConstMetric(c.assertionOutcome, prometheus.GaugeValue, 1,
			evidenceSource, campaign.Spec.NetworkRef, campaign.Name, result.Actor, result.Assertion, result.Outcome)
	}
	return valid
}

func (c *Collector) collectRun(output chan<- prometheus.Metric, run *attacknetv1beta1.AttacknetRun) bool {
	phase := run.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	attribution := run.Status.Attribution
	if attribution == "" {
		attribution = "Untriaged"
	}
	replay := run.Status.ScheduleSummary != nil && run.Status.ScheduleSummary.Replay
	scheduleDigest := ""
	if run.Status.ScheduleRef != nil {
		scheduleDigest = run.Status.ScheduleRef.Digest
	}
	output <- prometheus.MustNewConstMetric(c.runInfo, prometheus.GaugeValue, 1,
		evidenceSource, run.Spec.NetworkRef, run.Name, phase, run.Status.Reason, attribution,
		strconv.FormatBool(replay), strconv.FormatBool(run.Spec.Minimization.Enabled), scheduleDigest)
	if usage := run.Status.BudgetUsage; usage != nil {
		values := []struct {
			name  string
			value float64
		}{
			{"campaigns", float64(usage.Campaigns)},
			{"campaignsStarted", float64(usage.CampaignsStarted)},
			{"campaignsCompleted", float64(usage.CampaignsCompleted)},
			{"activeFaults", float64(usage.ActiveFaults)},
			{"activeCampaigns", float64(usage.ActiveCampaigns)},
			{"wallTimeSeconds", float64(usage.WallTimeMillis) / 1000},
			{"cumulativeFaultSeconds", float64(usage.CumulativeFaultMillis) / 1000},
			{"maximumSignerImpactPercent", float64(usage.MaximumSignerImpactBasisPoints) / 100},
			{"burnchainFaults", float64(usage.BurnchainFaults)},
			{"inconclusiveCampaigns", float64(usage.InconclusiveCampaigns)},
			{"minimizationAttempts", float64(usage.MinimizationAttempts)},
		}
		for _, value := range values {
			output <- prometheus.MustNewConstMetric(c.budgetUsage, prometheus.GaugeValue, value.value,
				evidenceSource, run.Spec.NetworkRef, run.Name, value.name)
		}
	}
	if classification := run.Status.TerminalClassification; classification != nil {
		output <- prometheus.MustNewConstMetric(c.minimization, prometheus.GaugeValue, 1,
			evidenceSource, run.Spec.NetworkRef, run.Name, classification.AttemptID,
			classification.CandidateScheduleDigest, classification.ExpectedAssertion,
			classification.ExpectedStatus, classification.Outcome, classification.Reason,
			classification.EvidenceDigest, strconv.FormatBool(classification.CausalMinimalityClaimed))
	}
	if assertions := run.Status.ProtocolAssertions; assertions != nil {
		return c.collectProtocolAssertions(output, run, "baseline", assertions.Baseline) &&
			c.collectProtocolAssertions(output, run, "during", assertions.During) &&
			c.collectProtocolAssertions(output, run, "recovery", assertions.Recovery)
	}
	return true
}

func (c *Collector) collectProtocolAssertions(output chan<- prometheus.Metric, run *attacknetv1beta1.AttacknetRun, gate string, status *attacknetv1beta1.ProtocolAssertionSetStatus) bool {
	if status == nil {
		return true
	}
	valid := true
	for _, result := range status.Results {
		output <- prometheus.MustNewConstMetric(c.protocolAssertion, prometheus.GaugeValue, 1,
			evidenceSource, run.Spec.NetworkRef, run.Name, gate, result.ID, result.Type, result.Outcome, result.Reason)
		sources, decoded := decodeProtocolSources(result.Evidence.Raw)
		valid = decoded && valid
		for _, source := range sources {
			output <- prometheus.MustNewConstMetric(c.protocolSource, prometheus.GaugeValue, 1,
				evidenceSource, run.Spec.NetworkRef, run.Name, gate, result.ID, source.Actor,
				source.Role, source.PodName, source.PodUID, source.RuntimeImageID,
				source.ServiceName, source.EvidenceClass)
			output <- prometheus.MustNewConstMetric(c.protocolSourceAt, prometheus.GaugeValue, float64(source.ObservedAt.UnixNano())/1e9,
				evidenceSource, run.Spec.NetworkRef, run.Name, gate, result.ID, source.Actor, source.PodUID)
		}
	}
	return valid
}

type protocolSource struct {
	Actor          string    `json:"actor"`
	Role           string    `json:"role"`
	PodName        string    `json:"podName"`
	PodUID         string    `json:"podUID"`
	RuntimeImageID string    `json:"runtimeImageID"`
	ServiceName    string    `json:"serviceName"`
	ObservedAt     time.Time `json:"observedAt"`
	EvidenceClass  string    `json:"evidenceClass"`
}

type protocolEvidence struct {
	Sources []protocolSource `json:"sources"`
}

func decodeProtocolSources(raw []byte) ([]protocolSource, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	value := protocolEvidence{}
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	for _, source := range value.Sources {
		if source.Actor == "" || source.Role == "" || source.PodName == "" ||
			source.PodUID == "" || source.RuntimeImageID == "" || source.ServiceName == "" ||
			source.ObservedAt.IsZero() || source.EvidenceClass == "" {
			return nil, false
		}
	}
	return value.Sources, true
}

type byteResult struct {
	Actor     string `json:"actor"`
	Assertion string `json:"assertion"`
	Outcome   string `json:"outcome"`
}

func decodeResults(values []apixv1.JSON) ([]byteResult, bool) {
	results := make([]byteResult, 0, len(values))
	valid := true
	for _, value := range values {
		result := byteResult{}
		if json.Unmarshal(value.Raw, &result) == nil && result.Assertion != "" && result.Outcome != "" {
			results = append(results, result)
		} else {
			valid = false
		}
	}
	return results, valid
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
