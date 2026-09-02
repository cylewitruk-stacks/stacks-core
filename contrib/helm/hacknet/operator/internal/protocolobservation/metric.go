package protocolobservation

import (
	"math"
	"time"
)

const maximumExactMetricInteger = float64(1<<53 - 1)

// IsFiniteNonNegative reports whether a scalar can represent a bounded metric
// value without introducing NaN, infinity, or a negative domain value.
func IsFiniteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

// IsBooleanGauge reports whether a scalar is the exact numeric representation
// of a false or true gauge.
func IsBooleanGauge(value float64) bool {
	return value == 0 || value == 1
}

// IsExactNonNegativeInteger reports whether a scalar can represent a height or
// count without lossy float-to-integer conversion.
func IsExactNonNegativeInteger(value float64) bool {
	return IsFiniteNonNegative(value) && math.Trunc(value) == value && value <= maximumExactMetricInteger
}

// MetricAge returns the signed age of a finite non-negative epoch timestamp.
// A future timestamp has a negative age so callers can distinguish a policy
// violation from unavailable or non-serializable evidence.
func MetricAge(now time.Time, epochSeconds float64) (time.Duration, bool) {
	if !IsFiniteNonNegative(epochSeconds) || epochSeconds > maximumExactMetricInteger {
		return 0, false
	}
	seconds, fraction := math.Modf(epochSeconds)
	observedAt := time.Unix(int64(seconds), int64(fraction*float64(time.Second))).UTC()
	return now.UTC().Sub(observedAt), true
}
