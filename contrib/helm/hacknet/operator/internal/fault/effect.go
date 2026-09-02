package fault

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

type effectEvaluation struct {
	Actor          string         `json:"actor"`
	Effect         string         `json:"effect"`
	Recovery       string         `json:"recovery"`
	Reason         string         `json:"reason"`
	RecoveryReason string         `json:"recoveryReason,omitempty"`
	Metrics        map[string]any `json:"metrics,omitempty"`
}

type effectReport struct {
	Verdict         string
	RecoveryVerdict string
	Evaluations     []effectEvaluation
}

type probePhase struct {
	Phase        string           `json:"phase"`
	Observations []map[string]any `json:"observations"`
}

func clockInjectionProven(campaign *attacknetv1alpha1.FaultCampaign, targets []attacknetv1alpha1.ResolvedTarget, artifacts map[string]string) (bool, error) {
	phases := map[string]probePhase{}
	selected := map[string]bool{}
	for _, target := range targets {
		selected[target.Actor] = true
	}
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	kind := definition.MutationKind
	for _, phase := range []string{"before", "during"} {
		value, err := decodeProbePhase(artifacts[phase+"Json"], phase, kind, selected)
		if err != nil {
			return false, err
		}
		phases[phase] = value
	}
	// evaluateClocks requires a complete phase set to select controls. Reusing
	// the during sample as the provisional after sample does not affect its
	// effect verdict; recovery is evaluated later from an independent sample.
	phases["after"] = probePhase{Phase: "after", Observations: phases["during"].Observations}
	if err := validateClockSemantics(phases, targets); err != nil {
		return false, err
	}
	proven := 0
	for _, evaluation := range evaluateClocks(campaign, targets, phases) {
		if evaluation.Effect == "proven" {
			proven++
		}
	}
	return proven >= expectedMinimum(campaign.Spec.Fault, len(targets)), nil
}

func evaluateProbeEvidence(campaign *attacknetv1alpha1.FaultCampaign, compiled Compiled, targets []attacknetv1alpha1.ResolvedTarget, artifacts map[string]string) (effectReport, error) {
	phases := map[string]probePhase{}
	selected := map[string]bool{}
	for _, target := range targets {
		selected[target.Actor] = true
	}
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	kind := definition.MutationKind
	for _, phase := range []string{"before", "during", "after"} {
		value, err := decodeProbePhase(artifacts[phase+"Json"], phase, kind, selected)
		if err != nil {
			return effectReport{}, err
		}
		phases[phase] = value
	}
	if definition.EffectKind == "clock" {
		if err := validateClockSemantics(phases, targets); err != nil {
			return effectReport{}, err
		}
	}
	return evaluateDecodedProbeEvidence(campaign, compiled, targets, phases)
}

// evaluateDuringProbeEvidence classifies effect evidence before mutation
// cleanup. Recovery intentionally remains inconclusive until an independent
// after-fault sample is captured.
func evaluateDuringProbeEvidence(campaign *attacknetv1alpha1.FaultCampaign, compiled Compiled, targets []attacknetv1alpha1.ResolvedTarget, artifacts map[string]string) (effectReport, error) {
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	if definition.EffectKind == "clock" {
		return effectReport{}, fmt.Errorf("clock effects require clockInjectionProven")
	}
	selected := map[string]bool{}
	for _, target := range targets {
		selected[target.Actor] = true
	}
	phases := map[string]probePhase{}
	for _, phase := range []string{"before", "during"} {
		value, err := decodeProbePhase(artifacts[phase+"Json"], phase, definition.MutationKind, selected)
		if err != nil {
			return effectReport{}, err
		}
		phases[phase] = value
	}
	phases["after"] = probePhase{Phase: "after"}
	return evaluateDecodedProbeEvidence(campaign, compiled, targets, phases)
}

func evaluateDecodedProbeEvidence(campaign *attacknetv1alpha1.FaultCampaign, compiled Compiled, targets []attacknetv1alpha1.ResolvedTarget, phases map[string]probePhase) (effectReport, error) {
	definition := mustMechanismForType(campaign.Spec.Fault.Type)
	byActor := func(phase string, actor string) []map[string]any {
		result := []map[string]any{}
		for _, item := range phases[phase].Observations {
			if item["actor"] == actor && item["status"] == "ok" {
				result = append(result, item)
			}
		}
		return result
	}
	evaluations := make([]effectEvaluation, 0, len(targets))
	if definition.EffectKind == "clock" {
		evaluations = evaluateClocks(campaign, targets, phases)
	} else {
		for _, target := range targets {
			before, during, after := byActor("before", target.Actor), byActor("during", target.Actor), byActor("after", target.Actor)
			var evaluation effectEvaluation
			switch definition.EffectKind {
			case "network":
				evaluation = evaluateNetwork(campaign.Spec.Fault.Action, compiled.Evidence.Parameters, target.Actor, before, during, after, set(compiled.Evidence.PeerSelectedActors))
			case "dns":
				evaluation = evaluateDNS(campaign.Spec.Fault.Action, compiled.Evidence.Parameters, target.Actor, before, during, after)
			case "io":
				evaluation = evaluateIO(campaign.Spec.Fault.Action, compiled.Evidence.Parameters, target.Actor, before, during, after)
			case "io-pressure":
				evaluation = evaluateIOPressure(compiled.Evidence.IOPressure, target.Actor, before, during, after)
			default:
				return effectReport{}, fmt.Errorf("unsupported probe evidence kind %s", definition.MutationKind)
			}
			evaluations = append(evaluations, evaluation)
		}
	}
	minimum := expectedMinimum(campaign.Spec.Fault, len(targets))
	proven, inconclusive := 0, 0
	for _, evaluation := range evaluations {
		switch evaluation.Effect {
		case "proven":
			proven++
		case "inconclusive":
			inconclusive++
		}
	}
	verdict := "Failed"
	if proven >= minimum {
		verdict = "Proven"
	} else if proven+inconclusive >= minimum {
		verdict = "Inconclusive"
	}
	recovery := "Inconclusive"
	affected := []effectEvaluation{}
	for _, evaluation := range evaluations {
		if evaluation.Effect == "proven" {
			affected = append(affected, evaluation)
		}
	}
	if len(affected) > 0 {
		recovery = "Proven"
		for _, evaluation := range affected {
			if evaluation.Recovery == "failed" {
				recovery = "Failed"
				break
			}
			if evaluation.Recovery == "inconclusive" {
				recovery = "Inconclusive"
			}
		}
	}
	return effectReport{Verdict: verdict, RecoveryVerdict: recovery, Evaluations: evaluations}, nil
}

func evaluateNetwork(action string, spec map[string]any, actor string, before, during, after []map[string]any, allowed map[string]bool) effectEvaluation {
	first, second := comparable(before, during, "network", allowed)
	if first == nil || second == nil || number(first["successes"]) == 0 {
		return inconclusive(actor, "named network probe lacked a healthy comparable baseline")
	}
	attemptsBefore, attemptsDuring := number(first["attempts"]), number(second["attempts"])
	beforeRate, duringRate := number(first["successes"])/attemptsBefore, number(second["successes"])/attemptsDuring
	latencyDelta := number(second["latencyMsP95"]) - number(first["latencyMsP95"])
	protocolDelta := number(second["protocolErrors"]) - number(first["protocolErrors"])
	beforeThroughput, beforeThroughputOK := finiteObservationNumber(first["throughputBytesPerSecond"])
	duringThroughput, duringThroughputOK := finiteObservationNumber(second["throughputBytesPerSecond"])
	if action == "bandwidth" && (!beforeThroughputOK || beforeThroughput <= 0 || !duringThroughputOK) {
		return inconclusive(actor, "bandwidth probe lacked comparable bounded throughput samples")
	}
	checks := []bool{}
	check := func(effect string) {
		switch effect {
		case "partition":
			checks = append(checks, duringRate == 0)
		case "delay":
			delay := nestedDuration(spec, "delay", "latency")
			checks = append(checks, latencyDelta >= math.Max(10, delay.Seconds()*500))
		case "loss":
			requested := nestedNumber(spec, "loss", "loss")
			checks = append(checks, (beforeRate-duringRate)*100 >= math.Max(5, requested*.5))
		case "duplicate", "corrupt":
			checks = append(checks, protocolDelta > 0)
		case "bandwidth":
			requested := bandwidthBytesPerSecond(spec)
			checks = append(checks, requested > 0 && duringThroughput <= requested*1.25 && duringThroughput/beforeThroughput < .8)
		}
	}
	if action == "netem" {
		for _, effect := range []string{"delay", "loss", "duplicate", "corrupt"} {
			if spec[effect] != nil {
				check(effect)
			}
		}
	} else {
		check(action)
	}
	proven := len(checks) > 0
	for _, value := range checks {
		proven = proven && value
	}
	if !proven {
		return failed(actor, "named network probes did not exhibit the requested delta")
	}
	final, _ := comparable(before, after, "network", allowed)
	recovery := "inconclusive"
	if final != nil {
		afterRate := number(final["successes"]) / number(final["attempts"])
		latencyOK := number(final["successes"]) > 0 && number(final["latencyMsP95"]) <= math.Max(number(first["latencyMsP95"])*2, number(first["latencyMsP95"])+50)
		throughputOK := true
		if action == "bandwidth" {
			afterThroughput, ok := finiteObservationNumber(final["throughputBytesPerSecond"])
			throughputOK = ok && afterThroughput >= beforeThroughput*.8
		}
		if afterRate >= math.Max(.5, beforeRate-.1) && latencyOK && throughputOK {
			recovery = "proven"
		} else {
			recovery = "failed"
		}
	}
	metrics := map[string]any{"beforeRate": beforeRate, "duringRate": duringRate, "latencyDeltaMs": latencyDelta, "protocolErrorDelta": protocolDelta}
	if action == "bandwidth" {
		metrics["throughputRatio"] = duringThroughput / beforeThroughput
		metrics["beforeThroughputBytesPerSecond"] = beforeThroughput
		metrics["duringThroughputBytesPerSecond"] = duringThroughput
	}
	return effectEvaluation{Actor: actor, Effect: "proven", Recovery: recovery, Reason: "named reachability/latency/throughput probe observed the requested effect", Metrics: metrics}
}

func finiteObservationNumber(value any) (float64, bool) {
	result := number(value)
	return result, !math.IsNaN(result) && !math.IsInf(result, 0) && result >= 0 && value != nil
}

func bandwidthBytesPerSecond(spec map[string]any) float64 {
	bandwidth, ok := spec["bandwidth"].(map[string]any)
	if !ok {
		return 0
	}
	match := rateRE.FindStringSubmatch(text(bandwidth["rate"]))
	if match == nil {
		return 0
	}
	amount, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0
	}
	return amount * map[string]float64{"bps": 1.0 / 8, "kbps": 1e3 / 8, "mbps": 1e6 / 8, "gbps": 1e9 / 8}[match[2]]
}

func evaluateDNS(action string, spec map[string]any, actor string, before, during, after []map[string]any) effectEvaluation {
	first, second := comparable(before, during, "dns", nil)
	if first == nil || second == nil || !boolean(first["querySucceeded"]) || !boolean(first["controlSucceeded"]) || !boolean(second["controlSucceeded"]) {
		return inconclusive(actor, "selected DNS probe lacked a healthy independent control")
	}
	patterns, _ := stringsValue(spec["patterns"], "patterns", true, nil)
	matched := false
	for _, pattern := range patterns {
		if glob(pattern, text(first["query"])) {
			matched = true
		}
	}
	if !matched {
		return inconclusive(actor, "no matching selected-query DNS probe")
	}
	proven := action == "error" && !boolean(second["querySucceeded"])
	if action == "random" {
		proven = boolean(second["querySucceeded"]) && !sameStrings(first["answers"], second["answers"])
	}
	if !proven {
		return failed(actor, "DNS probes did not isolate the requested effect from the control query")
	}
	final, _ := comparable(before, after, "dns", nil)
	recovery := "inconclusive"
	if final != nil {
		if boolean(final["querySucceeded"]) && boolean(final["controlSucceeded"]) && sameStrings(first["answers"], final["answers"]) {
			recovery = "proven"
		} else {
			recovery = "failed"
		}
	}
	return effectEvaluation{Actor: actor, Effect: "proven", Recovery: recovery, Reason: "selected DNS query changed while its independent control remained healthy"}
}

func evaluateIO(action string, spec map[string]any, actor string, before, during, after []map[string]any) effectEvaluation {
	first, second := comparable(before, during, "io", nil)
	if first == nil || second == nil || !ioObservationMatches(first, spec) || !ioObservationMatches(second, spec) {
		return inconclusive(actor, "no matching before/during I/O operation probe")
	}
	proven, metrics := false, map[string]any{}
	switch action {
	case "latency":
		if number(first["successes"]) == 0 || number(second["successes"]) == 0 {
			return inconclusive(actor, "I/O latency probe lacked a successful baseline")
		}
		requested, _ := time.ParseDuration(text(spec["delay"]))
		delta := number(second["latencyMsP95"]) - number(first["latencyMsP95"])
		proven = delta >= math.Max(5, requested.Seconds()*500)
		metrics["latencyDeltaMs"] = delta
	case "fault":
		errno := fmt.Sprint(int(number(spec["errno"])))
		delta := errorCount(second, errno) - errorCount(first, errno)
		proven = delta > 0
		metrics["errorCountDelta"] = delta
	case "attrOverride":
		proven = text(first["attributesDigest"]) != "" && text(second["attributesDigest"]) != "" && first["attributesDigest"] != second["attributesDigest"]
	case "mistake":
		proven = text(first["contentDigest"]) != "" && text(second["contentDigest"]) != "" && first["contentDigest"] != second["contentDigest"]
	}
	if !proven {
		return failed(actor, "I/O operation probes did not exhibit the requested effect")
	}
	final, _ := comparable(before, after, "io", nil)
	recovery := "inconclusive"
	if final != nil {
		recovered := false
		switch action {
		case "latency":
			recovered = number(final["latencyMsP95"]) <= math.Max(number(first["latencyMsP95"])*2, number(first["latencyMsP95"])+25)
		case "fault":
			errno := fmt.Sprint(int(number(spec["errno"])))
			recovered = errorCount(final, errno) <= errorCount(first, errno)
		case "attrOverride":
			recovered = first["attributesDigest"] == final["attributesDigest"]
		case "mistake":
			recovered = first["contentDigest"] == final["contentDigest"]
		}
		if recovered {
			recovery = "proven"
		} else {
			recovery = "failed"
		}
	}
	return effectEvaluation{Actor: actor, Effect: "proven", Recovery: recovery, Reason: "named I/O operation observed requested evidence", Metrics: metrics}
}

func ioObservationMatches(observation map[string]any, spec map[string]any) bool {
	path := text(observation["path"])
	if !strings.HasPrefix(path, text(spec["volumePath"])) {
		return false
	}
	if pattern := text(spec["path"]); pattern != "" && !glob(pattern, path) {
		return false
	}
	methods, ok := spec["methods"].([]any)
	if !ok || len(methods) == 0 {
		return true
	}
	operation := text(observation["operation"])
	for _, method := range methods {
		if text(method) == operation {
			return true
		}
	}
	return false
}

func evaluateIOPressure(contract map[string]any, actor string, before, during, after []map[string]any) effectEvaluation {
	first, second := comparable(before, during, "io", nil)
	if first == nil || second == nil || text(first["operation"]) != "FSYNC" || !strings.HasPrefix(text(first["path"]), "/data/") || number(first["successes"]) == 0 || number(second["successes"]) == 0 {
		return inconclusive(actor, "FSYNC pressure probe lacked a successful comparable baseline")
	}
	baseline := math.Max(number(first["latencyMsP95"]), .001)
	multiplier := number(second["latencyMsP95"]) / baseline
	added := number(second["latencyMsP95"]) - number(first["latencyMsP95"])
	proven := multiplier >= number(contract["minimumLatencyMultiplier"]) && added >= number(contract["minimumAddedLatencyMs"])
	if !proven {
		return failed(actor, "FSYNC latency did not meet both configured disk-pressure thresholds")
	}
	final, _ := comparable(before, after, "io", nil)
	recovery := "inconclusive"
	if final != nil && number(final["successes"]) > 0 {
		finalMultiplier := number(final["latencyMsP95"]) / baseline
		finalAdded := number(final["latencyMsP95"]) - number(first["latencyMsP95"])
		if finalMultiplier < number(contract["minimumLatencyMultiplier"]) && finalAdded < number(contract["minimumAddedLatencyMs"]) {
			recovery = "proven"
		} else {
			recovery = "failed"
		}
	}
	return effectEvaluation{Actor: actor, Effect: "proven", Recovery: recovery, Reason: "FSYNC latency met both configured disk-pressure thresholds", Metrics: map[string]any{"latencyMultiplier": multiplier, "addedLatencyMs": added}}
}

func evaluateClocks(campaign *attacknetv1alpha1.FaultCampaign, targets []attacknetv1alpha1.ResolvedTarget, phases map[string]probePhase) []effectEvaluation {
	phaseActor := func(phase, actor string) map[string]any {
		for _, item := range phases[phase].Observations {
			if item["actor"] == actor && item["status"] == "ok" && item["probe"] == "clock" {
				return item
			}
		}
		return nil
	}
	controls := []string{}
	targetNames := map[string]bool{}
	for _, target := range targets {
		targetNames[target.Actor] = true
	}
	for _, item := range phases["before"].Observations {
		if item["probe"] == "clock" && item["status"] == "ok" && boolean(item["control"]) {
			actor := text(item["actor"])
			during := phaseActor("during", actor)
			after := phaseActor("after", actor)
			if !targetNames[actor] && during != nil && after != nil &&
				boolean(during["control"]) && boolean(after["control"]) &&
				number(during["monotonicSeconds"]) >= number(item["monotonicSeconds"]) &&
				number(after["monotonicSeconds"]) >= number(item["monotonicSeconds"]) {
				controls = append(controls, actor)
			}
		}
	}
	if len(controls) == 0 {
		result := make([]effectEvaluation, len(targets))
		for index, target := range targets {
			result[index] = inconclusive(target.Actor, "no independent control clock was observed in all phases")
		}
		return result
	}
	controlShift := func(phase string) float64 {
		values := []float64{}
		for _, actor := range controls {
			values = append(values, clockShift(phaseActor("before", actor), phaseActor(phase, actor)))
		}
		sort.Float64s(values)
		middle := len(values) / 2
		if len(values)%2 == 1 {
			return values[middle]
		}
		return (values[middle-1] + values[middle]) / 2
	}
	duringControl, afterControl := controlShift("during"), controlShift("after")
	requested, _ := time.ParseDuration(strings.TrimPrefix(text(parameterMap(campaign.Spec.Fault.Parameters.Raw)["timeOffset"]), "+"))
	tolerance := math.Max(1, math.Min(5, math.Abs(requested.Seconds())*.2))
	result := []effectEvaluation{}
	for _, target := range targets {
		first, second, final := phaseActor("before", target.Actor), phaseActor("during", target.Actor), phaseActor("after", target.Actor)
		if first == nil || second == nil || number(second["monotonicSeconds"]) < number(first["monotonicSeconds"]) ||
			(final != nil && number(final["monotonicSeconds"]) < number(first["monotonicSeconds"])) {
			result = append(result, inconclusive(target.Actor, "target clock probe is missing or monotonic time moved backwards"))
			continue
		}
		observed := clockShift(first, second) - duringControl
		effect := "failed"
		if math.Abs(observed-requested.Seconds()) <= tolerance {
			effect = "proven"
		}
		recovery := "inconclusive"
		recoveredOffset := 0.0
		if final != nil {
			recoveredOffset = clockShift(first, final) - afterControl
			if math.Abs(recoveredOffset) <= tolerance {
				recovery = "proven"
			} else {
				recovery = "failed"
			}
		}
		result = append(result, effectEvaluation{Actor: target.Actor, Effect: effect, Recovery: recovery, Reason: "wall-clock shift compared with monotonic and independent control clocks", Metrics: map[string]any{"requestedOffsetSeconds": requested.Seconds(), "observedOffsetSeconds": observed, "recoveredOffsetSeconds": recoveredOffset, "toleranceSeconds": tolerance, "controlActors": controls}})
	}
	return result
}

func comparable(before, other []map[string]any, probe string, allowed map[string]bool) (map[string]any, map[string]any) {
	for _, first := range before {
		if first["probe"] != probe {
			continue
		}
		if allowed != nil && len(allowed) > 0 && !allowed[text(first["peerActor"])] {
			continue
		}
		key := observationKey(first)
		for _, second := range other {
			if second["probe"] == probe && observationKey(second) == key {
				return first, second
			}
		}
	}
	return nil, nil
}

func observationKey(value map[string]any) string {
	return strings.Join([]string{text(value["probeName"]), text(value["peerActor"]), text(value["query"]), text(value["controlQuery"]), text(value["path"]), text(value["operation"])}, "\x00")
}

func expectedMinimum(spec attacknetv1alpha1.FaultSpec, candidates int) int {
	switch spec.Mode {
	case "all":
		return candidates
	case "fixed":
		return spec.Value.IntValue()
	case "fixed-percent":
		return int(math.Ceil(float64(candidates) * float64(spec.Value.IntValue()) / 100))
	default:
		return 1
	}
}

func nestedDuration(values map[string]any, outer, inner string) time.Duration {
	value, _ := values[outer].(map[string]any)
	parsed, _ := time.ParseDuration(text(value[inner]))
	return parsed
}

func nestedNumber(values map[string]any, outer, inner string) float64 {
	value, _ := values[outer].(map[string]any)
	return number(value[inner])
}

func errorCount(value map[string]any, errno string) float64 {
	counts, _ := value["errorCounts"].(map[string]any)
	return number(counts[errno])
}

func clockShift(first, second map[string]any) float64 {
	return (number(second["wallEpochSeconds"]) - number(first["wallEpochSeconds"])) - (number(second["monotonicSeconds"]) - number(first["monotonicSeconds"]))
}

func sameStrings(left, right any) bool {
	normalize := func(raw any) []string {
		items, _ := raw.([]any)
		values := make([]string, len(items))
		for index := range items {
			values[index] = text(items[index])
		}
		sort.Strings(values)
		return values
	}
	return strings.Join(normalize(left), "\x00") == strings.Join(normalize(right), "\x00")
}

func glob(pattern, value string) bool {
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, `\*`, `.*`)
	matched, _ := regexp.MatchString("^"+expression+"$", value)
	return matched
}

func parameterMap(raw []byte) map[string]any {
	value := map[string]any{}
	_ = json.Unmarshal(raw, &value)
	return value
}

func number(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	default:
		return 0
	}
}

func text(value any) string {
	text, _ := value.(string)
	return text
}

func boolean(value any) bool {
	result, _ := value.(bool)
	return result
}

func inconclusive(actor, reason string) effectEvaluation {
	return effectEvaluation{Actor: actor, Effect: "inconclusive", Recovery: "inconclusive", Reason: reason}
}

func failed(actor, reason string) effectEvaluation {
	return effectEvaluation{Actor: actor, Effect: "failed", Recovery: "inconclusive", Reason: reason}
}
