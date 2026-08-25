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

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
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
		collectionSuccess: prometheus.NewDesc("attacknet_orchestrator_metrics_collection_success", "Whether the latest orchestration state collection succeeded.", nil, nil),
	}
}

// Describe publishes every descriptor owned by the collector.
func (c *Collector) Describe(output chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{c.campaignInfo, c.campaignTarget, c.assertionOutcome, c.runInfo, c.budgetUsage, c.minimization, c.collectionSuccess} {
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
	campaigns := &attacknetv1alpha1.FaultCampaignList{}
	runs := &attacknetv1alpha1.AttacknetRunList{}
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
		c.collectRun(output, &runs.Items[index])
	}
	output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, boolFloat(success))
}

func (c *Collector) collectCampaign(output chan<- prometheus.Metric, campaign *attacknetv1alpha1.FaultCampaign) bool {
	phase := campaign.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	output <- prometheus.MustNewConstMetric(c.campaignInfo, prometheus.GaugeValue, 1,
		evidenceSource, campaign.Spec.NetworkRef, campaign.Name, campaign.Spec.Fault.Type, phase,
		campaign.Status.Reason, strconv.FormatBool(campaign.Spec.Template))
	for _, target := range campaign.Status.ResolvedTargets {
		output <- prometheus.MustNewConstMetric(c.campaignTarget, prometheus.GaugeValue, 1,
			evidenceSource, campaign.Spec.NetworkRef, campaign.Name, target.Actor, target.Role, target.Node)
	}
	effects, effectsValid := decodeResults(campaign.Status.EffectResults)
	recoveries, recoveriesValid := decodeResults(campaign.Status.RecoveryResults)
	for _, raw := range append(effects, recoveries...) {
		output <- prometheus.MustNewConstMetric(c.assertionOutcome, prometheus.GaugeValue, 1,
			evidenceSource, campaign.Spec.NetworkRef, campaign.Name, raw.Actor, raw.Assertion, raw.Outcome)
	}
	return effectsValid && recoveriesValid
}

func (c *Collector) collectRun(output chan<- prometheus.Metric, run *attacknetv1alpha1.AttacknetRun) {
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
			{"wallTimeSeconds", usage.WallTimeSeconds},
			{"cumulativeFaultSeconds", usage.CumulativeFaultSeconds},
			{"maximumSignerImpactPercent", usage.MaximumSignerImpactPercent},
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
