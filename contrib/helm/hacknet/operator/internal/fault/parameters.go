package fault

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

var (
	ioMethods        = stringSet("READ", "WRITE", "FLUSH", "FSYNC", "FDATASYNC", "READDIR", "SYNC", "OPEN", "MKDIR", "MKNOD", "CHOWN", "CHMOD", "UTIMES", "LINK", "UNLINK", "RENAME")
	clockIDs         = stringSet("CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_PROCESS_CPUTIME_ID", "CLOCK_THREAD_CPUTIME_ID")
	rateRE           = regexp.MustCompile(`^(\d+(?:\.\d+)?)(bps|kbps|mbps|gbps)$`)
	durationRE       = regexp.MustCompile(`^(\d+)(ms|s|m|h)$`)
	signedDurationRE = regexp.MustCompile(`^([+-]?)(\d+)(ms|s|m|h)$`)
)

type parameterResult struct {
	Parameters         map[string]any
	PeerSelectedActors []string
	IOPressure         map[string]any
}

type pressureLimit struct {
	workers  int
	bytesMiB int
	duration time.Duration
}

var pressureLimits = map[string]pressureLimit{
	"low":    {workers: 1, bytesMiB: 64, duration: time.Minute},
	"medium": {workers: 2, bytesMiB: 256, duration: 3 * time.Minute},
	"high":   {workers: 4, bytesMiB: 512, duration: 5 * time.Minute},
}

func validateParameters(kind, action string, parameters map[string]any, safety attacknetv1alpha1.FaultSafety, duration time.Duration, manifest Manifest) (parameterResult, error) {
	result := parameterResult{Parameters: cloneMap(parameters)}
	definition, err := mechanismForType(kind)
	if err != nil {
		return result, err
	}
	if len(definition.AllowedActions) > 0 && !definition.AllowedActions[action] {
		return result, fmt.Errorf("unsupported %s action %s", kind, action)
	}
	if len(definition.AllowedActions) == 0 && action != "" {
		return result, fmt.Errorf("%s faults must not specify action", kind)
	}
	return definition.Parameters(action, result.Parameters, safety, duration, manifest)
}

func podParameterValidator(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety, _ time.Duration, _ Manifest) (parameterResult, error) {
	result := parameterResult{Parameters: values}
	return result, validatePodParameters(action, values, safety)
}

func networkParameterValidator(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety, _ time.Duration, manifest Manifest) (parameterResult, error) {
	result := parameterResult{Parameters: values}
	var err error
	result.PeerSelectedActors, err = validateNetworkParameters(action, values, safety, manifest)
	return result, err
}

func dnsParameterValidator(_ string, values map[string]any, _ attacknetv1alpha1.FaultSafety, _ time.Duration, _ Manifest) (parameterResult, error) {
	return parameterResult{Parameters: values}, validateDNSParameters(values)
}

func ioParameterValidator(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety, _ time.Duration, _ Manifest) (parameterResult, error) {
	return parameterResult{Parameters: values}, validateIOParameters(action, values, safety)
}

func ioPressureParameterValidator(_ string, values map[string]any, safety attacknetv1alpha1.FaultSafety, duration time.Duration, _ Manifest) (parameterResult, error) {
	parameters, evidence, err := validateIOPressureParameters(values, safety, duration)
	return parameterResult{Parameters: parameters, IOPressure: evidence}, err
}

func timeParameterValidator(_ string, values map[string]any, safety attacknetv1alpha1.FaultSafety, _ time.Duration, _ Manifest) (parameterResult, error) {
	return parameterResult{Parameters: values}, validateTimeParameters(values, safety, false)
}

func clockSkewParameterValidator(_ string, values map[string]any, safety attacknetv1alpha1.FaultSafety, _ time.Duration, _ Manifest) (parameterResult, error) {
	return parameterResult{Parameters: values}, validateTimeParameters(values, safety, true)
}

func validatePodParameters(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety) error {
	allowed := map[string]bool{}
	if action == "container-kill" {
		allowed["containerNames"] = true
	}
	if action == "pod-kill" {
		allowed["gracePeriod"] = true
	}
	if err := rejectUnknown(values, allowed); err != nil {
		return err
	}
	if action == "container-kill" {
		if _, err := stringsValue(values["containerNames"], "containerNames", true, nil); err != nil {
			return err
		}
	}
	if value, ok := values["gracePeriod"]; ok {
		number, err := numberValue(value, "gracePeriod", 0, 3600, true)
		if err != nil {
			return err
		}
		if number > 60 && !safety.AllowExtremeSeverity {
			return errors.New("gracePeriod above 60s requires safety.allowExtremeSeverity=true")
		}
	}
	return nil
}

func validateNetworkParameters(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety, manifest Manifest) ([]string, error) {
	actionFields := map[string][]string{
		"netem": {"delay", "loss", "duplicate", "corrupt"}, "delay": {"delay"}, "loss": {"loss"},
		"duplicate": {"duplicate"}, "corrupt": {"corrupt"}, "partition": {}, "bandwidth": {"bandwidth"},
	}[action]
	allowed := stringSet("direction", "peerTarget", "harnessTarget", "target", "targetDevice", "device", "externalTargets")
	for _, field := range actionFields {
		allowed[field] = true
	}
	if err := rejectUnknown(values, allowed); err != nil {
		return nil, err
	}
	if direction, ok := values["direction"]; ok && direction != "to" && direction != "from" && direction != "both" {
		return nil, errors.New("direction must be to, from, or both")
	}
	for _, field := range []string{"targetDevice", "device"} {
		if value, ok := values[field]; ok {
			if _, ok := value.(string); !ok || value == "" || len(value.(string)) > 64 {
				return nil, fmt.Errorf("%s must be a non-empty string of at most 64 characters", field)
			}
		}
	}
	forms := 0
	for _, field := range []string{"target", "peerTarget", "harnessTarget", "externalTargets"} {
		if _, ok := values[field]; ok {
			forms++
		}
	}
	if forms > 1 {
		return nil, errors.New("use exactly one of peerTarget, harnessTarget, raw target, or externalTargets")
	}
	if (values["target"] != nil || values["externalTargets"] != nil) && !safety.AllowUnenrolledTargets {
		return nil, errors.New("raw target/externalTargets require safety.allowUnenrolledNetworkTargets=true")
	}
	peerNames := []string{}
	if raw, ok := values["peerTarget"]; ok {
		target, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("peerTarget must be an object")
		}
		if err := rejectUnknown(target, stringSet("actors", "roles", "mode", "value")); err != nil {
			return nil, fmt.Errorf("peerTarget: %w", err)
		}
		actors, err := optionalStrings(target["actors"], "peerTarget.actors")
		if err != nil {
			return nil, err
		}
		roles, err := optionalStrings(target["roles"], "peerTarget.roles")
		if err != nil {
			return nil, err
		}
		if len(actors)+len(roles) == 0 {
			return nil, errors.New("peerTarget requires actors or roles")
		}
		selected, err := selectActors(attacknetv1alpha1.FaultTarget{Actors: actors, Roles: roles}, manifest.Actors)
		if err != nil {
			return nil, fmt.Errorf("peerTarget: %w", err)
		}
		mode := "all"
		if rawMode, exists := target["mode"]; exists {
			text, ok := rawMode.(string)
			if !ok {
				return nil, errors.New("peerTarget.mode must be a string")
			}
			mode = text
		}
		value := ""
		if rawValue, ok := target["value"]; ok {
			value = fmt.Sprint(rawValue)
		}
		maximum, normalized, err := normalizeNestedMode(mode, value, len(selected))
		if err != nil {
			return nil, err
		}
		_ = maximum
		selector := actorSelector(manifest, actors, roles)
		compiled := map[string]any{"mode": mode, "selector": selector}
		if normalized != "" {
			compiled["value"] = normalized
		}
		values["target"] = compiled
		delete(values, "peerTarget")
		for _, actor := range selected {
			peerNames = append(peerNames, actor.Name)
		}
	} else if raw, ok := values["harnessTarget"]; ok {
		if raw != "prometheus" {
			return nil, fmt.Errorf("unsupported harnessTarget %v", raw)
		}
		values["target"] = map[string]any{"mode": "all", "selector": map[string]any{
			"namespaces":     []any{manifest.Namespace},
			"labelSelectors": map[string]any{NetworkLabel: manifest.Network, "app.kubernetes.io/name": "attacknet-prometheus"},
		}}
		delete(values, "harnessTarget")
		peerNames = []string{"attacknet-prometheus"}
	} else if raw, ok := values["target"]; ok {
		if _, ok := raw.(map[string]any); !ok {
			return nil, errors.New("target must be an object")
		}
	} else if raw, ok := values["externalTargets"]; ok {
		if _, err := stringsValue(raw, "externalTargets", true, nil); err != nil {
			return nil, err
		}
	}
	if direction, _ := values["direction"].(string); (direction == "from" || direction == "both") && values["target"] == nil {
		return nil, fmt.Errorf("network direction %s requires peerTarget, harnessTarget, or raw target", direction)
	}
	if action == "netem" {
		found := false
		for _, field := range actionFields {
			_, found = values[field]
			if found {
				break
			}
		}
		if !found {
			return nil, errors.New("network netem requires delay, loss, duplicate, or corrupt parameters")
		}
	} else if action == "partition" {
		if values["target"] == nil && values["externalTargets"] == nil {
			return nil, errors.New("network partition requires peerTarget, harnessTarget, raw target, or externalTargets")
		}
	} else if values[action] == nil {
		return nil, fmt.Errorf("network %s requires parameters.%s", action, action)
	}
	if raw, ok := values["delay"]; ok {
		if err := validateDelay(raw, safety); err != nil {
			return nil, err
		}
	}
	for _, field := range []string{"loss", "duplicate", "corrupt"} {
		if raw, ok := values[field]; ok {
			if err := validatePacketEffect(raw, field, safety); err != nil {
				return nil, err
			}
		}
	}
	if raw, ok := values["bandwidth"]; ok {
		if err := validateBandwidth(raw, safety); err != nil {
			return nil, err
		}
	}
	if values["target"] != nil && values["direction"] == nil {
		values["direction"] = "both"
	}
	sort.Strings(peerNames)
	return peerNames, nil
}

func validateDNSParameters(values map[string]any) error {
	if err := rejectUnknown(values, stringSet("patterns", "containerNames")); err != nil {
		return err
	}
	patterns, err := stringsValue(values["patterns"], "patterns", true, nil)
	if err != nil {
		return err
	}
	for _, pattern := range patterns {
		if len(pattern) > 253 {
			return errors.New("DNS pattern exceeds 253 characters")
		}
	}
	if raw, ok := values["containerNames"]; ok {
		_, err = stringsValue(raw, "containerNames", true, nil)
	}
	return err
}

func validateIOParameters(action string, values map[string]any, safety attacknetv1alpha1.FaultSafety) error {
	actionField := map[string]string{"latency": "delay", "fault": "errno", "attrOverride": "attr", "mistake": "mistake"}[action]
	allowed := stringSet("volumePath", "path", "methods", "percent", "containerNames", actionField)
	if err := rejectUnknown(values, allowed); err != nil {
		return err
	}
	volume, ok := values["volumePath"].(string)
	if !ok || volume == "" || len(volume) > 4096 || !strings.HasPrefix(volume, "/") {
		return errors.New("volumePath must be a non-empty absolute path")
	}
	if raw, ok := values["path"]; ok {
		path, ok := raw.(string)
		if !ok || path == "" || len(path) > 4096 || !strings.HasPrefix(path, "/") {
			return errors.New("path must be a non-empty absolute path")
		}
	}
	for _, field := range []string{"methods", "containerNames"} {
		if raw, ok := values[field]; ok {
			allowedValues := map[string]bool(nil)
			if field == "methods" {
				allowedValues = ioMethods
			}
			if _, err := stringsValue(raw, field, true, allowedValues); err != nil {
				return err
			}
		}
	}
	if raw, ok := values["percent"]; ok {
		if _, err := percentage(raw, "percent", safety, 50); err != nil {
			return err
		}
	}
	raw, ok := values[actionField]
	if !ok {
		return fmt.Errorf("I/O %s requires parameters.%s", action, actionField)
	}
	switch action {
	case "latency":
		delay, err := boundedDuration(raw, "delay", false)
		if err != nil {
			return err
		}
		if delay > 5*time.Second && !safety.AllowExtremeSeverity {
			return errors.New("delay above 5s requires safety.allowExtremeSeverity=true")
		}
	case "fault":
		_, err := numberValue(raw, "errno", 1, 4095, true)
		return err
	default:
		object, ok := raw.(map[string]any)
		if !ok || len(object) == 0 {
			return fmt.Errorf("%s must be a non-empty object", actionField)
		}
	}
	return nil
}

func validateIOPressureParameters(values map[string]any, safety attacknetv1alpha1.FaultSafety, duration time.Duration) (map[string]any, map[string]any, error) {
	allowed := stringSet("containerNames", "severity", "workers", "bytesMiB", "writeSizeKiB", "minimumLatencyMultiplier", "minimumAddedLatencyMs")
	if err := rejectUnknown(values, allowed); err != nil {
		return nil, nil, err
	}
	for field := range allowed {
		if _, ok := values[field]; !ok {
			return nil, nil, fmt.Errorf("disk-pressure requires fault.parameters.%s", field)
		}
	}
	containers, err := stringsValue(values["containerNames"], "containerNames", true, nil)
	if err != nil || len(containers) != 1 || containers[0] != "actor" {
		return nil, nil, errors.New("disk-pressure must select exactly the actor container")
	}
	severity, ok := values["severity"].(string)
	limit, known := pressureLimits[severity]
	if !ok || !known {
		return nil, nil, errors.New("severity must be low, medium, or high")
	}
	if severity == "high" && !safety.AllowExtremeSeverity {
		return nil, nil, errors.New("high disk-pressure severity requires safety.allowExtremeSeverity=true")
	}
	if duration > limit.duration {
		return nil, nil, fmt.Errorf("%s disk-pressure duration must not exceed %s", severity, limit.duration)
	}
	workers, err := numberValue(values["workers"], "workers", 1, float64(limit.workers), true)
	if err != nil {
		return nil, nil, err
	}
	bytesMiB, err := numberValue(values["bytesMiB"], "bytesMiB", 16, float64(limit.bytesMiB), true)
	if err != nil {
		return nil, nil, err
	}
	writeSize, err := numberValue(values["writeSizeKiB"], "writeSizeKiB", 4, 1024, true)
	if err != nil {
		return nil, nil, err
	}
	if writeSize > bytesMiB*1024 {
		return nil, nil, errors.New("writeSizeKiB must not exceed bytesMiB")
	}
	multiplier, err := numberValue(values["minimumLatencyMultiplier"], "minimumLatencyMultiplier", 1.1, 20, false)
	if err != nil {
		return nil, nil, err
	}
	added, err := numberValue(values["minimumAddedLatencyMs"], "minimumAddedLatencyMs", 0.5, 5000, false)
	if err != nil {
		return nil, nil, err
	}
	execution := map[string]any{"containerNames": []any{"actor"}, "workers": workers, "bytesMiB": bytesMiB, "writeSizeKiB": writeSize}
	evidence := map[string]any{"semantic": "disk-io-pressure", "severity": severity, "workers": workers, "bytesMiB": bytesMiB, "writeSizeKiB": writeSize, "tempPath": "/data", "minimumLatencyMultiplier": multiplier, "minimumAddedLatencyMs": added}
	return execution, evidence, nil
}

func validateTimeParameters(values map[string]any, safety attacknetv1alpha1.FaultSafety, application bool) error {
	if err := rejectUnknown(values, stringSet("timeOffset", "clockIds", "containerNames")); err != nil {
		return err
	}
	offset, err := boundedDuration(values["timeOffset"], "timeOffset", true)
	if err != nil {
		return err
	}
	if absDuration(offset) > 24*time.Hour {
		return errors.New("timeOffset must not exceed 24h")
	}
	if absDuration(offset) > 5*time.Minute && !safety.AllowExtremeSeverity {
		return errors.New("timeOffset beyond 5m requires safety.allowExtremeSeverity=true")
	}
	clocks := []string{}
	if raw, ok := values["clockIds"]; ok {
		clocks, err = stringsValue(raw, "clockIds", true, clockIDs)
		if err != nil {
			return err
		}
	}
	containers := []string{}
	if raw, ok := values["containerNames"]; ok {
		containers, err = stringsValue(raw, "containerNames", true, nil)
		if err != nil {
			return err
		}
		if len(containers) > 1 {
			return errors.New("TimeChaos may select at most one container per Pod")
		}
	}
	if application {
		if len(clocks) > 0 && (len(clocks) != 1 || clocks[0] != "CLOCK_REALTIME") {
			return errors.New("application clock-skew supports only CLOCK_REALTIME")
		}
		if len(containers) > 0 && (len(containers) != 1 || containers[0] != "actor") {
			return errors.New("application clock-skew must select exactly the actor container")
		}
	}
	return nil
}

func validateDelay(raw any, safety attacknetv1alpha1.FaultSafety) error {
	value, ok := raw.(map[string]any)
	if !ok {
		return errors.New("delay must be an object")
	}
	if err := rejectUnknown(value, stringSet("latency", "correlation", "jitter")); err != nil {
		return err
	}
	latency, err := boundedDuration(value["latency"], "delay.latency", false)
	if err != nil {
		return err
	}
	if latency > 5*time.Second && !safety.AllowExtremeSeverity {
		return errors.New("delay.latency above 5s requires safety.allowExtremeSeverity=true")
	}
	if jitter, ok := value["jitter"]; ok {
		if _, err := boundedDurationAllowZero(jitter, "delay.jitter"); err != nil {
			return err
		}
	}
	if correlation, ok := value["correlation"]; ok {
		_, err = percentage(correlation, "delay.correlation", safety, 100)
	}
	return err
}

func validatePacketEffect(raw any, field string, safety attacknetv1alpha1.FaultSafety) error {
	value, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", field)
	}
	if err := rejectUnknown(value, stringSet(field, "correlation")); err != nil {
		return err
	}
	if _, ok := value[field]; !ok {
		return fmt.Errorf("%s.%s is required", field, field)
	}
	if _, err := percentage(value[field], field+"."+field, safety, 50); err != nil {
		return err
	}
	if correlation, ok := value["correlation"]; ok {
		_, err := percentage(correlation, field+".correlation", safety, 100)
		return err
	}
	return nil
}

func validateBandwidth(raw any, safety attacknetv1alpha1.FaultSafety) error {
	value, ok := raw.(map[string]any)
	if !ok {
		return errors.New("bandwidth must be an object")
	}
	if err := rejectUnknown(value, stringSet("rate", "limit", "buffer", "peakrate", "minburst")); err != nil {
		return err
	}
	rate, ok := value["rate"].(string)
	match := rateRE.FindStringSubmatch(rate)
	if !ok || match == nil {
		return errors.New("bandwidth.rate must be a bps/kbps/mbps/gbps rate")
	}
	amount, _ := numberValue(match[1], "bandwidth.rate", 0, math.MaxFloat64, false)
	scalar := map[string]float64{"bps": 1, "kbps": 1e3, "mbps": 1e6, "gbps": 1e9}[match[2]]
	if amount*scalar < 10_000 && !safety.AllowExtremeSeverity {
		return errors.New("bandwidth.rate below 10kbps requires safety.allowExtremeSeverity=true")
	}
	for _, field := range []string{"limit", "buffer", "minburst"} {
		if rawNumber, ok := value[field]; ok {
			if _, err := numberValue(rawNumber, "bandwidth."+field, 1, math.MaxInt32, true); err != nil {
				return err
			}
		}
	}
	if peak, ok := value["peakrate"]; ok {
		text, ok := peak.(string)
		if !ok || text == "" || len(text) > 64 {
			return errors.New("bandwidth.peakrate must be a non-empty string of at most 64 characters")
		}
	}
	return nil
}

func actorSelector(manifest Manifest, actors, roles []string) map[string]any {
	expressions := []any{}
	if len(actors) > 0 {
		expressions = append(expressions, map[string]any{"key": ActorLabel, "operator": "In", "values": stringAny(actors)})
	}
	if len(roles) > 0 {
		expressions = append(expressions, map[string]any{"key": RoleLabel, "operator": "In", "values": stringAny(roles)})
	}
	return map[string]any{"namespaces": []any{manifest.Namespace}, "labelSelectors": map[string]any{NetworkLabel: manifest.Network}, "expressionSelectors": expressions}
}

func normalizeNestedMode(mode, value string, count int) (int, string, error) {
	if mode == "one" || mode == "all" {
		if value != "" {
			return 0, "", fmt.Errorf("value is forbidden when mode is %s", mode)
		}
		if mode == "one" {
			return 1, "", nil
		}
		return count, "", nil
	}
	if value == "" {
		return 0, "", fmt.Errorf("value is required when mode is %s", mode)
	}
	valueNumber, err := numberValue(value, "value", 1, 100, true)
	if err != nil {
		return 0, "", err
	}
	if mode == "fixed" {
		if valueNumber > float64(count) {
			return 0, "", errors.New("fixed value exceeds candidate count")
		}
		return int(valueNumber), fmt.Sprint(int(valueNumber)), nil
	}
	if mode != "fixed-percent" && mode != "random-max-percent" {
		return 0, "", fmt.Errorf("unsupported fault mode %s", mode)
	}
	return int(math.Ceil(float64(count) * valueNumber / 100)), fmt.Sprint(int(valueNumber)), nil
}

func rejectUnknown(values map[string]any, allowed map[string]bool) error {
	for field := range values {
		if !allowed[field] {
			return fmt.Errorf("unsupported fault.parameters field %s", field)
		}
	}
	return nil
}

func optionalStrings(raw any, field string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return stringsValue(raw, field, false, nil)
}

func stringsValue(raw any, field string, required bool, allowed map[string]bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	if len(values) > 256 {
		return nil, fmt.Errorf("%s must contain at most 256 entries", field)
	}
	seen, result := map[string]bool{}, make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok || text == "" || len(text) > 1024 {
			return nil, fmt.Errorf("%s[%d] must be a non-empty string", field, index)
		}
		if allowed != nil && !allowed[text] {
			return nil, fmt.Errorf("%s[%d] has unsupported value %s", field, index, text)
		}
		if seen[text] {
			return nil, fmt.Errorf("%s must not contain duplicates", field)
		}
		seen[text], result[index] = true, text
	}
	return result, nil
}

func numberValue(raw any, field string, minimum, maximum float64, integer bool) (float64, error) {
	var value float64
	switch typed := raw.(type) {
	case float64:
		value = typed
	case float32:
		value = float64(typed)
	case int:
		value = float64(typed)
	case int32:
		value = float64(typed)
	case int64:
		value = float64(typed)
	case string:
		if !regexp.MustCompile(`^(?:0|[1-9]\d*)(?:\.\d+)?$`).MatchString(typed) {
			return 0, fmt.Errorf("%s must be a finite numeric value", field)
		}
		if _, err := fmt.Sscan(typed, &value); err != nil {
			return 0, fmt.Errorf("%s must be a finite numeric value", field)
		}
	default:
		return 0, fmt.Errorf("%s must be a finite numeric value", field)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < minimum || value > maximum || (integer && math.Trunc(value) != value) {
		return 0, fmt.Errorf("%s must be a finite %snumber in %g..%g", field, ternaryString(integer, "integer ", ""), minimum, maximum)
	}
	return value, nil
}

func percentage(raw any, field string, safety attacknetv1alpha1.FaultSafety, extremeAbove float64) (float64, error) {
	value, err := numberValue(raw, field, 0, 100, false)
	if err != nil {
		return 0, err
	}
	if value > extremeAbove && !safety.AllowExtremeSeverity {
		return 0, fmt.Errorf("%s above %g%% requires safety.allowExtremeSeverity=true", field, extremeAbove)
	}
	return value, nil
}

func boundedDuration(raw any, field string, signed bool) (time.Duration, error) {
	return parseBoundedDuration(raw, field, signed, false)
}

func boundedDurationAllowZero(raw any, field string) (time.Duration, error) {
	return parseBoundedDuration(raw, field, false, true)

}

func parseBoundedDuration(raw any, field string, signed, allowZero bool) (time.Duration, error) {
	text, ok := raw.(string)
	expression := durationRE
	if signed {
		expression = signedDurationRE
	}
	if !ok || expression.FindStringSubmatch(text) == nil {
		return 0, fmt.Errorf("%s must use an integer %sms/s/m/h value", field, ternaryString(signed, "signed ", ""))
	}
	parsed, err := time.ParseDuration(strings.TrimPrefix(text, "+"))
	if err != nil || (!allowZero && parsed == 0) {
		return 0, fmt.Errorf("%s must use a %sinteger %sms/s/m/h value", field, ternaryString(allowZero, "non-negative ", "non-zero "), ternaryString(signed, "signed ", ""))
	}
	return parsed, nil
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func stringSet(values ...string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func ternaryString(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}
