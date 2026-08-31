// Package orchestratormetrics exports bounded, controller-observed Attacknet state.
package orchestratormetrics

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/adversarial"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/versionmatrix"
)

const (
	evidenceSource      = "orchestrator_observed"
	actorEvidenceSource = "actor_self_reported"
)

// Collector reads cached controller state and exposes the finite Attacknet
// campaign/run metric contract used by dashboards and evidence collection.
type Collector struct {
	Reader client.Reader

	campaignInfo        *prometheus.Desc
	upgradeInfo         *prometheus.Desc
	actorVersion        *prometheus.Desc
	adversarialPolicy   *prometheus.Desc
	versionCapability   *prometheus.Desc
	campaignTarget      *prometheus.Desc
	faultAction         *prometheus.Desc
	assertionOutcome    *prometheus.Desc
	runInfo             *prometheus.Desc
	budgetUsage         *prometheus.Desc
	minimization        *prometheus.Desc
	protocolAssertion   *prometheus.Desc
	protocolSource      *prometheus.Desc
	protocolSourceAt    *prometheus.Desc
	stacksBurnHeight    *prometheus.Desc
	stacksBurnView      *prometheus.Desc
	burnchainTopology   *prometheus.Desc
	burnchainGeneration *prometheus.Desc
	bitcoinNode         *prometheus.Desc
	bitcoinEdge         *prometheus.Desc
	burnchainBinding    *prometheus.Desc
	collectionSuccess   *prometheus.Desc
}

// NewCollector constructs an Attacknet orchestration collector.
func NewCollector(reader client.Reader) *Collector {
	return &Collector{
		Reader: reader,
		campaignInfo: prometheus.NewDesc("attacknet_fault_campaign_info", "Current orchestrator-observed FaultCampaign state.",
			[]string{"evidence_source", "network", "campaign", "type", "phase", "reason", "template"}, nil),
		upgradeInfo: prometheus.NewDesc("attacknet_upgrade_campaign_info", "Current topology-owned UpgradeCampaign state.",
			[]string{"evidence_source", "network", "campaign", "phase", "reason", "stage", "template"}, nil),
		actorVersion: prometheus.NewDesc("attacknet_actor_version_info", "Static or rolling actor version identity joined to immutable provenance.",
			[]string{"evidence_source", "attacknet_network", "campaign", "attacknet_actor", "profile", "source_kind", "revision", "image", "runtime_image_id", "provenance_digest", "config_digest", "expectation"}, nil),
		adversarialPolicy: prometheus.NewDesc("attacknet_adversarial_policy_info", "Admitted testing-only signer policy and isolated observer identity.",
			[]string{"evidence_source", "network", "actor", "behavior", "policy_digest", "egress_profile", "egress_policy_digest", "observer", "observer_ready"}, nil),
		versionCapability: prometheus.NewDesc("attacknet_actor_version_capability_info", "Finite instrumentation capability declared by one actor version profile.",
			[]string{"evidence_source", "attacknet_network", "attacknet_actor", "profile", "capability"}, nil),
		campaignTarget: prometheus.NewDesc("attacknet_fault_campaign_target_info", "Exact actor targets admitted for a FaultCampaign.",
			[]string{"evidence_source", "network", "campaign", "actor", "role", "node"}, nil),
		faultAction: prometheus.NewDesc("attacknet_fault_action_info", "Current orchestrator-observed state of one typed fault action.",
			[]string{"evidence_source", "network", "campaign", "stage", "action", "type", "phase", "reason"}, nil),
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
		stacksBurnHeight: prometheus.NewDesc("attacknet_run_stacks_burn_view_height", "Burn height in one identity-bound Stacks actor branch observation.",
			[]string{"evidence_source", "network", "run", "gate", "assertion", "actor", "bitcoin_node"}, nil),
		stacksBurnView: prometheus.NewDesc("attacknet_run_stacks_burn_view_fingerprint", "Exact 52-bit visualization fingerprint of one identity-bound Stacks burn consensus hash; full hashes remain in evidence.",
			[]string{"evidence_source", "network", "run", "gate", "assertion", "actor", "bitcoin_node"}, nil),
		burnchainTopology: prometheus.NewDesc("attacknet_burnchain_topology_info", "Current complete Bitcoin topology admitted by the topology operator.",
			[]string{"evidence_source", "network"}, nil),
		burnchainGeneration: prometheus.NewDesc("attacknet_burnchain_topology_observed_generation", "StacksNetwork generation represented by the admitted Bitcoin topology.",
			[]string{"evidence_source", "network"}, nil),
		bitcoinNode: prometheus.NewDesc("attacknet_burnchain_node_info", "Bitcoin node and cadence-policy identity admitted by the topology operator.",
			[]string{"evidence_source", "network", "bitcoin_node", "service", "policy", "policy_uid", "policy_service"}, nil),
		bitcoinEdge: prometheus.NewDesc("attacknet_burnchain_topology_edge_info", "Directed persistent Bitcoin P2P edge admitted by the topology operator.",
			[]string{"evidence_source", "network", "source", "target"}, nil),
		burnchainBinding: prometheus.NewDesc("attacknet_burnchain_actor_binding_info", "Stacks actor to Bitcoin node binding admitted by the topology operator.",
			[]string{"evidence_source", "network", "actor", "bitcoin_node"}, nil),
		collectionSuccess: prometheus.NewDesc("attacknet_orchestrator_metrics_collection_success", "Whether the latest orchestration state collection succeeded.", nil, nil),
	}
}

// Describe publishes every descriptor owned by the collector.
func (c *Collector) Describe(output chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{c.campaignInfo, c.upgradeInfo, c.actorVersion, c.adversarialPolicy, c.versionCapability, c.campaignTarget, c.faultAction, c.assertionOutcome, c.runInfo, c.budgetUsage, c.minimization, c.protocolAssertion, c.protocolSource, c.protocolSourceAt, c.stacksBurnHeight, c.stacksBurnView, c.burnchainTopology, c.burnchainGeneration, c.bitcoinNode, c.bitcoinEdge, c.burnchainBinding, c.collectionSuccess} {
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
	upgrades := &attacknetv1beta1.UpgradeCampaignList{}
	runs := &attacknetv1beta1.AttacknetRunList{}
	networks := &attacknetv1beta1.StacksNetworkList{}
	if err := c.Reader.List(ctx, campaigns); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	if err := c.Reader.List(ctx, upgrades); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	if err := c.Reader.List(ctx, runs); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	if err := c.Reader.List(ctx, networks); err != nil {
		output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, 0)
		return
	}
	success := true
	for index := range campaigns.Items {
		success = c.collectCampaign(output, &campaigns.Items[index]) && success
	}
	for index := range upgrades.Items {
		c.collectUpgrade(output, &upgrades.Items[index])
	}
	for index := range runs.Items {
		success = c.collectRun(output, &runs.Items[index]) && success
	}
	for index := range networks.Items {
		success = c.collectNetwork(output, &networks.Items[index], upgrades.Items) && success
	}
	output <- prometheus.MustNewConstMetric(c.collectionSuccess, prometheus.GaugeValue, boolFloat(success))
}

func (c *Collector) collectNetwork(output chan<- prometheus.Metric, network *attacknetv1beta1.StacksNetwork, upgrades []attacknetv1beta1.UpgradeCampaign) bool {
	versions := map[string]actorVersionSample{}
	if encoded := network.Annotations[versionmatrix.RuntimeManifestAnnotation]; encoded != "" {
		manifest, err := versionmatrix.ParseRuntimeManifest(encoded)
		if err != nil {
			return false
		}
		profiles := map[string]versionmatrix.RuntimeProfile{}
		for _, profile := range manifest.Profiles {
			profiles[profile.Name] = profile
		}
		actors := map[string]attacknetv1beta1.ActorStatus{}
		for _, actor := range network.Status.Actors {
			actors[actor.Name] = actor
		}
		for _, assignment := range manifest.Assignments {
			profile, profileOK := profiles[assignment.Profile]
			actor, actorOK := actors[assignment.Actor]
			if !profileOK || !actorOK {
				return false
			}
			versions[assignment.Actor] = actorVersionSample{campaign: "static", profile: profile.Name, sourceKind: profile.SourceKind, revision: profile.Revision, image: profile.Image, runtimeImageID: actor.RuntimeImageID, provenanceDigest: profile.ProvenanceDigest, configDigest: assignment.ConfigDigest, expectation: profile.Expectation, capabilities: profile.Capabilities}
		}
	}
	statuses := map[string]attacknetv1beta1.ActorStatus{}
	for _, actor := range network.Status.Actors {
		statuses[actor.Name] = actor
	}
	for _, set := range network.Spec.SignerSets {
		for _, member := range set.Members {
			if member.Adversarial == nil {
				continue
			}
			policy, digest, err := adversarial.ResolveSigner(network, member.Name)
			if err != nil {
				return false
			}
			signer, signerOK := statuses[member.Name]
			observerName := adversarial.ObserverName(member.Name)
			observer, observerOK := statuses[observerName]
			if !signerOK || !signer.IdentityReady || signer.AdversarialPolicyDigest != digest || signer.AdversarialEgressProfile != member.Adversarial.Egress.Profile || !observerOK || observer.AdversarialPolicyDigest != digest {
				return false
			}
			output <- prometheus.MustNewConstMetric(c.adversarialPolicy, prometheus.GaugeValue, 1,
				evidenceSource, network.Name, member.Name, policy.Behavior, digest,
				member.Adversarial.Egress.Profile, signer.EgressPolicyDigest, observerName, strconv.FormatBool(observer.IdentityReady))
		}
	}
	for index := range upgrades {
		campaign := &upgrades[index]
		if campaign.Spec.Template || campaign.Spec.NetworkRef != network.Name || !upgradeVersionActive(campaign) {
			continue
		}
		profiles := map[string]attacknetv1beta1.UpgradeProfileSpec{}
		for _, profile := range campaign.Spec.Profiles {
			profiles[profile.Name] = profile
		}
		for _, assignment := range campaign.Status.AppliedAssignments {
			profile, profileOK := profiles[assignment.Profile]
			actor, actorOK := statuses[assignment.Actor]
			if !profileOK || !actorOK || actor.Image != profile.Image || !inventory.RuntimeImageMatches(actor.RuntimeImageID, profile.ImageID) {
				continue
			}
			configDigest := ""
			if assignment.Config != nil && assignment.Config.ExpectedDigest != "" {
				configDigest = assignment.Config.ExpectedDigest
			}
			versions[assignment.Actor] = actorVersionSample{campaign: campaign.Name, profile: profile.Name, sourceKind: profile.SourceKind, revision: profile.Revision, image: profile.Image, runtimeImageID: actor.RuntimeImageID, provenanceDigest: profile.ProvenanceDigest, configDigest: configDigest, expectation: profile.Expectation, capabilities: profile.Capabilities}
		}
	}
	actors := make([]string, 0, len(versions))
	for actor := range versions {
		actors = append(actors, actor)
	}
	sort.Strings(actors)
	for _, actor := range actors {
		version := versions[actor]
		c.emitActorVersion(output, network.Name, version.campaign, actor, version.profile, version.sourceKind, version.revision, version.image, version.runtimeImageID, version.provenanceDigest, version.configDigest, version.expectation, version.capabilities)
	}
	topology := network.Status.BurnchainTopology
	if topology == nil || topology.Digest == "" {
		return true
	}
	output <- prometheus.MustNewConstMetric(c.burnchainTopology, prometheus.GaugeValue, 1,
		evidenceSource, network.Name)
	output <- prometheus.MustNewConstMetric(c.burnchainGeneration, prometheus.GaugeValue, float64(topology.ObservedGeneration),
		evidenceSource, network.Name)
	for _, node := range topology.Nodes {
		output <- prometheus.MustNewConstMetric(c.bitcoinNode, prometheus.GaugeValue, 1,
			evidenceSource, network.Name, node.Name, node.ServiceName, node.PolicyRef,
			node.PolicyUID, node.PolicyServiceName)
		for _, peer := range node.PeerRefs {
			output <- prometheus.MustNewConstMetric(c.bitcoinEdge, prometheus.GaugeValue, 1,
				evidenceSource, network.Name, node.Name, peer)
		}
	}
	for _, binding := range topology.Bindings {
		output <- prometheus.MustNewConstMetric(c.burnchainBinding, prometheus.GaugeValue, 1,
			evidenceSource, network.Name, binding.Actor, binding.BitcoinNodeRef)
	}
	return true
}

func (c *Collector) collectUpgrade(output chan<- prometheus.Metric, campaign *attacknetv1beta1.UpgradeCampaign) {
	phase := campaign.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	stage := ""
	if campaign.Status.CurrentStage >= 0 && int(campaign.Status.CurrentStage) < len(campaign.Spec.Stages) {
		stage = campaign.Spec.Stages[campaign.Status.CurrentStage].Name
	}
	output <- prometheus.MustNewConstMetric(c.upgradeInfo, prometheus.GaugeValue, 1,
		evidenceSource, campaign.Spec.NetworkRef, campaign.Name, phase, campaign.Status.Reason, stage, strconv.FormatBool(campaign.Spec.Template))
}

type actorVersionSample struct {
	campaign, profile, sourceKind, revision, image, runtimeImageID string
	provenanceDigest, configDigest, expectation                    string
	capabilities                                                   []string
}

func upgradeVersionActive(campaign *attacknetv1beta1.UpgradeCampaign) bool {
	switch campaign.Status.Phase {
	case "Running", "Passed":
		return true
	case "Failed", "Inconclusive":
		return campaign.Status.BaselineInventory != nil && !campaign.Status.RollbackComplete
	default:
		return false
	}
}

func (c *Collector) emitActorVersion(output chan<- prometheus.Metric, network, campaign, actor, profile, sourceKind, revision, image, runtimeImageID, provenanceDigest, configDigest, expectation string, capabilities []string) {
	output <- prometheus.MustNewConstMetric(c.actorVersion, prometheus.GaugeValue, 1,
		evidenceSource, network, campaign, actor, profile, sourceKind, revision, image,
		runtimeImageID, provenanceDigest, configDigest, expectation)
	for _, capability := range capabilities {
		output <- prometheus.MustNewConstMetric(c.versionCapability, prometheus.GaugeValue, 1,
			evidenceSource, network, actor, profile, capability)
	}
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
			faultType := campaignFaultType(campaign, stage.ID, action.ID)
			actionPhase := action.Phase
			if actionPhase == "" {
				actionPhase = "Pending"
			}
			output <- prometheus.MustNewConstMetric(c.faultAction, prometheus.GaugeValue, 1,
				evidenceSource, campaign.Spec.NetworkRef, campaign.Name, stage.ID, action.ID, faultType, actionPhase, action.Reason)
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

func campaignFaultType(campaign *attacknetv1beta1.FaultCampaign, stageID, actionID string) string {
	for _, stage := range campaign.Spec.Stages {
		if stage.ID != stageID {
			continue
		}
		for _, action := range stage.Faults {
			if action.ID == actionID {
				return action.Fault.Type
			}
		}
	}
	return "unknown"
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
		views, decoded := decodeStacksBurnViews(result.Type, result.Outcome, result.Evidence.Raw)
		valid = decoded && valid
		for _, view := range views {
			output <- prometheus.MustNewConstMetric(c.stacksBurnHeight, prometheus.GaugeValue, float64(view.BurnBlockHeight),
				actorEvidenceSource, run.Spec.NetworkRef, run.Name, gate, result.ID, view.Actor, view.BitcoinNodeRef)
			output <- prometheus.MustNewConstMetric(c.stacksBurnView, prometheus.GaugeValue, float64(view.Fingerprint),
				actorEvidenceSource, run.Spec.NetworkRef, run.Name, gate, result.ID, view.Actor, view.BitcoinNodeRef)
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

type stacksBurnView struct {
	Actor           string
	BitcoinNodeRef  string
	BurnBlockHeight uint64
	Fingerprint     uint64
}

type stacksBurnViewValue struct {
	BurnBlockHeight   uint64 `json:"burnBlockHeight"`
	BurnConsensusHash string `json:"burnConsensusHash"`
	BitcoinNodeRef    string `json:"bitcoinNodeRef"`
}

type stacksBranchEvidence struct {
	StacksObservations map[string]stacksBurnViewValue `json:"stacksObservations"`
}

func decodeStacksBurnViews(assertionType, outcome string, raw []byte) ([]stacksBurnView, bool) {
	if assertionType != "StacksBurnchainCohort" {
		return nil, true
	}
	if len(raw) == 0 {
		return nil, outcome != "Proven"
	}
	value := stacksBranchEvidence{}
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	actors := make([]string, 0, len(value.StacksObservations))
	for actor := range value.StacksObservations {
		actors = append(actors, actor)
	}
	if outcome == "Proven" && len(actors) == 0 {
		return nil, false
	}
	sort.Strings(actors)
	views := make([]stacksBurnView, 0, len(actors))
	for _, actor := range actors {
		observed := value.StacksObservations[actor]
		if actor == "" || observed.BitcoinNodeRef == "" || !fixedLowerHex(observed.BurnConsensusHash, 40) {
			return nil, false
		}
		fingerprint, err := strconv.ParseUint(observed.BurnConsensusHash[:13], 16, 52)
		if err != nil {
			return nil, false
		}
		views = append(views, stacksBurnView{Actor: actor, BitcoinNodeRef: observed.BitcoinNodeRef,
			BurnBlockHeight: observed.BurnBlockHeight, Fingerprint: fingerprint})
	}
	return views, true
}

func fixedLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
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
