// Package instrumentationprofile owns the finite version-capability vocabulary
// consumed by mixed-version observability.
package instrumentationprofile

var supported = map[string]struct{}{
	"M01": {}, "M02": {}, "M03": {}, "M04": {}, "M05": {}, "M06": {}, "M07": {},
	"M08": {}, "M09": {}, "M10": {}, "M11": {}, "M12": {}, "M13": {}, "M15": {},
	"M16": {}, "M17": {}, "M18": {}, "M19": {}, "M20": {}, "M21": {}, "M22": {},
}

// Valid reports whether value names one portable instrumentation family.
func Valid(value string) bool {
	_, ok := supported[value]
	return ok
}

// Validate rejects duplicates and unknown capability identifiers.
func Validate(values []string) bool {
	if len(values) > len(supported) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !Valid(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
