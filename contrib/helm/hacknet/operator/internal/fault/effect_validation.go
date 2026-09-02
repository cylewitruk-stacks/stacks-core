package fault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

const faultProbeSchema = "stacks-attacknet-fault-probe/v1"

var phaseFields = fieldSet("schemaVersion", "phase", "source", "capturedAt", "injection", "observations")

// decodeProbePhase validates an orchestrator-produced probe artifact before it
// can contribute to a fault verdict.
func decodeProbePhase(encoded, expectedPhase, kind string, selectedActors map[string]bool) (probePhase, error) {
	definition, err := mechanismForMutationKind(kind)
	if err != nil {
		return probePhase{}, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(encoded))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return probePhase{}, fmt.Errorf("decode %s probe evidence: %w", expectedPhase, err)
	}
	if err := exactObject(raw, phaseFields, expectedPhase); err != nil {
		return probePhase{}, err
	}
	if raw["schemaVersion"] != faultProbeSchema {
		return probePhase{}, fmt.Errorf("%s.schemaVersion must be %s", expectedPhase, faultProbeSchema)
	}
	if raw["phase"] != expectedPhase {
		return probePhase{}, fmt.Errorf("%s probe evidence declares phase %v", expectedPhase, raw["phase"])
	}
	if captured, ok := raw["capturedAt"]; ok {
		value, ok := captured.(string)
		if !ok {
			return probePhase{}, fmt.Errorf("%s.capturedAt must be RFC 3339", expectedPhase)
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return probePhase{}, fmt.Errorf("%s.capturedAt must be RFC 3339: %w", expectedPhase, err)
		}
	}
	if err := validateProbeSource(raw["source"], expectedPhase+".source", kind); err != nil {
		return probePhase{}, err
	}
	if injection, ok := raw["injection"]; ok {
		if err := validateProbeInjection(injection, expectedPhase+".injection", kind); err != nil {
			return probePhase{}, err
		}
	}
	observations, ok := raw["observations"].([]any)
	if !ok || len(observations) > 10_000 {
		return probePhase{}, fmt.Errorf("%s.observations must be an array of at most 10000 entries", expectedPhase)
	}
	result := probePhase{Phase: expectedPhase, Observations: make([]map[string]any, 0, len(observations))}
	seen := map[string]bool{}
	for index, item := range observations {
		observation, ok := item.(map[string]any)
		if !ok {
			return probePhase{}, fmt.Errorf("%s.observations[%d] must be an object", expectedPhase, index)
		}
		field := fmt.Sprintf("%s.observations[%d]", expectedPhase, index)
		if err := validateObservation(observation, field, kind); err != nil {
			return probePhase{}, err
		}
		actor := text(observation["actor"])
		if definition.EffectKind != "clock" && !selectedActors[actor] {
			return probePhase{}, fmt.Errorf("%s contains non-target actor %s", field, actor)
		}
		if observation["status"] == "ok" {
			key := actor + "\x00" + observationKey(observation)
			if seen[key] {
				return probePhase{}, fmt.Errorf("%s contains duplicate observation key for actor %s", expectedPhase, actor)
			}
			seen[key] = true
		}
		result.Observations = append(result.Observations, observation)
	}
	return result, nil
}

func validateProbeSource(value any, field, kind string) error {
	definition, err := mechanismForMutationKind(kind)
	if err != nil {
		return err
	}
	source, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", field)
	}
	if err := exactObject(source, fieldSet("trust", "authority", "collector", "contentTrust"), field); err != nil {
		return err
	}
	authority := "active-probe"
	clock := definition.EffectKind == "clock"
	if clock {
		authority = "application-process-metric"
	}
	if source["trust"] != "orchestrator-observed" || source["authority"] != authority {
		return fmt.Errorf("%s must be orchestrator-observed %s", field, authority)
	}
	if err := boundedString(source["collector"], field+".collector", 256); err != nil {
		return err
	}
	if clock && source["contentTrust"] != "actor-self-reported" {
		return fmt.Errorf("%s.contentTrust must disclose actor-self-reported time content", field)
	}
	if !clock && source["contentTrust"] != nil {
		return fmt.Errorf("%s.contentTrust is only valid for clock evidence", field)
	}
	return nil
}

func validateProbeInjection(value any, field, kind string) error {
	definition, err := mechanismForMutationKind(kind)
	if err != nil {
		return err
	}
	injection, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", field)
	}
	if err := exactObject(injection, fieldSet("allInjectedObserved", "source"), field); err != nil {
		return err
	}
	if _, ok := injection["allInjectedObserved"].(bool); !ok {
		return fmt.Errorf("%s.allInjectedObserved must be a boolean", field)
	}
	source, ok := injection["source"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s.source must be an object", field)
	}
	if err := exactObject(source, fieldSet("trust", "authority", "collector"), field+".source"); err != nil {
		return err
	}
	authority := "chaos-mesh-status"
	if definition.Backend == ioPressureBackend {
		authority = "kubernetes-pod-status"
	} else if definition.Backend == clockPolicyBackend {
		authority = "controller-clock-policy"
	}
	if source["trust"] != "orchestrator-observed" || source["authority"] != authority {
		return fmt.Errorf("%s.source must be orchestrator-observed %s", field, authority)
	}
	return boundedString(source["collector"], field+".source.collector", 256)
}

func validateObservation(value map[string]any, field, kind string) error {
	definition, err := mechanismForMutationKind(kind)
	if err != nil {
		return err
	}
	probe := definition.ProbeKind
	if probe == "" {
		return fmt.Errorf("unsupported probe evidence kind %s", kind)
	}
	if err := boundedString(value["actor"], field+".actor", 253); err != nil {
		return err
	}
	if value["probe"] != probe {
		return fmt.Errorf("%s.probe must be %s", field, probe)
	}
	status, ok := value["status"].(string)
	if !ok || (status != "ok" && status != "error") {
		return fmt.Errorf("%s.status must be ok or error", field)
	}
	allowed := observationFields(probe)
	if err := exactObject(value, allowed, field); err != nil {
		return err
	}
	if status == "error" {
		return boundedString(value["error"], field+".error", 4096)
	}
	if _, exists := value["error"]; exists {
		return fmt.Errorf("%s.error is only valid when status=error", field)
	}
	switch probe {
	case "network":
		return validateNetworkObservation(value, field)
	case "dns":
		return validateDNSObservation(value, field)
	case "io":
		return validateIOObservation(value, field)
	case "clock":
		return validateClockObservation(value, field)
	default:
		return fmt.Errorf("unsupported probe %s", probe)
	}
}

func observationFields(probe string) map[string]bool {
	common := []string{"actor", "probe", "status", "error"}
	fields := map[string][]string{
		"network": {"probeName", "peerActor", "attempts", "successes", "latencyMsP50", "latencyMsP95", "protocolErrors", "throughputBytesPerSecond"},
		"dns":     {"probeName", "query", "controlQuery", "querySucceeded", "controlSucceeded", "answers", "controlAnswers"},
		"io":      {"probeName", "path", "operation", "attempts", "successes", "errorCounts", "latencyMsP50", "latencyMsP95", "contentDigest", "attributesDigest"},
		"clock":   {"control", "wallEpochSeconds", "monotonicSeconds", "sampleWindowMs", "metric"},
	}[probe]
	return fieldSet(append(common, fields...)...)
}

func validateNetworkObservation(value map[string]any, field string) error {
	for _, entry := range []struct {
		key string
		max int
	}{{"probeName", 128}, {"peerActor", 253}} {
		if err := boundedString(value[entry.key], field+"."+entry.key, entry.max); err != nil {
			return err
		}
	}
	attempts, err := boundedNumber(value["attempts"], field+".attempts", 1, 10_000, true)
	if err != nil {
		return err
	}
	successes, err := boundedNumber(value["successes"], field+".successes", 0, attempts, true)
	if err != nil {
		return err
	}
	for _, key := range []string{"latencyMsP50", "latencyMsP95"} {
		if value[key] != nil {
			if _, err := boundedNumber(value[key], field+"."+key, 0, 3_600_000, false); err != nil {
				return err
			}
		}
	}
	if successes > 0 && (value["latencyMsP50"] == nil || value["latencyMsP95"] == nil) {
		return fmt.Errorf("%s needs latency values when successes > 0", field)
	}
	if _, err := boundedNumber(defaultNumber(value["protocolErrors"]), field+".protocolErrors", 0, attempts, true); err != nil {
		return err
	}
	if value["throughputBytesPerSecond"] != nil {
		_, err = boundedNumber(value["throughputBytesPerSecond"], field+".throughputBytesPerSecond", 0, 1e15, false)
	}
	return err
}

func validateDNSObservation(value map[string]any, field string) error {
	for _, entry := range []struct {
		key string
		max int
	}{{"probeName", 128}, {"query", 253}, {"controlQuery", 253}} {
		if err := boundedString(value[entry.key], field+"."+entry.key, entry.max); err != nil {
			return err
		}
	}
	for _, key := range []string{"querySucceeded", "controlSucceeded"} {
		if _, ok := value[key].(bool); !ok {
			return fmt.Errorf("%s.%s must be a boolean", field, key)
		}
	}
	for _, key := range []string{"answers", "controlAnswers"} {
		if err := validateStringArray(value[key], field+"."+key, 256); err != nil {
			return err
		}
	}
	return nil
}

func validateIOObservation(value map[string]any, field string) error {
	for _, entry := range []struct {
		key string
		max int
	}{{"probeName", 128}, {"path", 4096}, {"operation", 64}} {
		if err := boundedString(value[entry.key], field+"."+entry.key, entry.max); err != nil {
			return err
		}
	}
	attempts, err := boundedNumber(value["attempts"], field+".attempts", 1, 10_000, true)
	if err != nil {
		return err
	}
	successes, err := boundedNumber(value["successes"], field+".successes", 0, attempts, true)
	if err != nil {
		return err
	}
	errors, ok := value["errorCounts"].(map[string]any)
	if !ok || len(errors) > 128 {
		return fmt.Errorf("%s.errorCounts must be a bounded object", field)
	}
	total := successes
	for errno, count := range errors {
		parsedErrno, parseErrno := strconv.Atoi(errno)
		if parseErrno != nil || parsedErrno < 1 || parsedErrno > 4095 || strconv.Itoa(parsedErrno) != errno {
			return fmt.Errorf("%s.errorCounts contains invalid errno %s", field, errno)
		}
		parsed, parseErr := boundedNumber(count, field+".errorCounts."+errno, 0, attempts, true)
		if parseErr != nil {
			return parseErr
		}
		total += parsed
	}
	if total > attempts {
		return fmt.Errorf("%s successes plus errors exceeds attempts", field)
	}
	for _, key := range []string{"latencyMsP50", "latencyMsP95"} {
		if _, err := boundedNumber(value[key], field+"."+key, 0, 3_600_000, false); err != nil {
			return err
		}
	}
	for _, key := range []string{"contentDigest", "attributesDigest"} {
		if value[key] != nil {
			if err := boundedString(value[key], field+"."+key, 256); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateClockObservation(value map[string]any, field string) error {
	if _, ok := value["control"].(bool); !ok {
		return fmt.Errorf("%s.control must be a boolean", field)
	}
	for _, entry := range []struct {
		key     string
		maximum float64
	}{{"wallEpochSeconds", 1e12}, {"monotonicSeconds", 1e12}, {"sampleWindowMs", 5000}} {
		if _, err := boundedNumber(value[entry.key], field+"."+entry.key, 0, entry.maximum, false); err != nil {
			return err
		}
	}
	if value["metric"] != "stacks_node_process_wall_clock_seconds" {
		return fmt.Errorf("%s.metric must be stacks_node_process_wall_clock_seconds", field)
	}
	return nil
}

func fieldSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func exactObject(value map[string]any, allowed map[string]bool, field string) error {
	for key := range value {
		if !allowed[key] {
			return fmt.Errorf("%s contains unsupported field %s", field, key)
		}
	}
	return nil
}

func boundedString(value any, field string, maximum int) error {
	text, ok := value.(string)
	if !ok || len(text) == 0 || len(text) > maximum {
		return fmt.Errorf("%s must be a non-empty string of at most %d characters", field, maximum)
	}
	return nil
}

func boundedNumber(value any, field string, minimum, maximum float64, integer bool) (float64, error) {
	result := number(value)
	if value == nil || math.IsNaN(result) || math.IsInf(result, 0) || result < minimum || result > maximum || (integer && math.Trunc(result) != result) {
		return 0, fmt.Errorf("%s must be a finite number in %v..%v", field, minimum, maximum)
	}
	return result, nil
}

func defaultNumber(value any) any {
	if value == nil {
		return json.Number("0")
	}
	return value
}

func validateStringArray(value any, field string, maximum int) error {
	items, ok := value.([]any)
	if !ok || len(items) > maximum {
		return fmt.Errorf("%s must be an array of at most %d strings", field, maximum)
	}
	seen := map[string]bool{}
	for index, item := range items {
		if err := boundedString(item, fmt.Sprintf("%s[%d]", field, index), 1024); err != nil {
			return err
		}
		text := item.(string)
		if seen[text] {
			return fmt.Errorf("%s must not contain duplicates", field)
		}
		seen[text] = true
	}
	return nil
}

func validateClockSemantics(phases map[string]probePhase, targets []attacknetv1alpha1.ResolvedTarget) error {
	targetNames := map[string]bool{}
	for _, target := range targets {
		targetNames[target.Actor] = true
	}
	for phase, value := range phases {
		for _, observation := range value.Observations {
			if observation["status"] != "ok" || observation["probe"] != "clock" {
				continue
			}
			if targetNames[text(observation["actor"])] && boolean(observation["control"]) {
				return fmt.Errorf("selected actor %s cannot be marked as a clock control in %s", observation["actor"], phase)
			}
		}
	}
	return nil
}
