package protocolobservation

import (
	"math"
	"testing"
	"time"
)

func TestMetricDomainsRejectLossyAndNonFiniteValues(t *testing.T) {
	for _, value := range []float64{-1, 1.5, math.NaN(), math.Inf(1), 1 << 53} {
		if IsExactNonNegativeInteger(value) {
			t.Fatalf("lossy or invalid metric integer passed: %v", value)
		}
	}
	if !IsExactNonNegativeInteger(1<<53 - 1) {
		t.Fatal("largest exactly representable metric integer was rejected")
	}
	for _, value := range []float64{-1, 0.5, 2, math.NaN(), math.Inf(1)} {
		if IsBooleanGauge(value) {
			t.Fatalf("invalid boolean gauge passed: %v", value)
		}
	}
	if !IsBooleanGauge(0) || !IsBooleanGauge(1) {
		t.Fatal("valid boolean gauge was rejected")
	}
}

func TestMetricAgePreservesSignedFiniteAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if age, valid := MetricAge(now, float64(now.Add(time.Minute).Unix())); !valid || age != -time.Minute {
		t.Fatalf("future timestamp did not retain signed age: %s, %v", age, valid)
	}
	for _, value := range []float64{-1, math.NaN(), math.Inf(1), 1 << 53} {
		if _, valid := MetricAge(now, value); valid {
			t.Fatalf("invalid timestamp passed: %v", value)
		}
	}
}
