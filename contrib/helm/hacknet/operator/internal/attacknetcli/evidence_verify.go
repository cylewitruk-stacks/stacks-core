package attacknetcli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/probeattribution"
)

// SignerReportVerification is the bounded result of verifying one signed
// adversarial-signer observer report.
type SignerReportVerification struct {
	SchemaVersion string `json:"schemaVersion"`
	Outcome       string `json:"outcome"`
	PayloadDigest string `json:"payloadDigest"`
	KeyID         string `json:"keyId"`
	ObservedAt    string `json:"observedAt"`
}

func optionalTime(value, name string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339: %w", name, err)
	}
	return parsed, nil
}

func (app *App) runVerifySignerReport(args []string) error {
	flags := newFlagSet("evidence verify-signer-report", app.Stderr)
	file := flags.String("file", "", "signed report JSON path")
	actor := flags.String("actor", "", "expected observer actor")
	target := flags.String("target", "", "expected signer actor")
	policy := flags.String("policy-digest", "", "expected normalized policy digest")
	nonce := flags.String("nonce", "", "expected challenge nonce")
	keyID := flags.String("key-id", "", "optional expected observer key digest")
	notBeforeValue := flags.String("not-before", "", "optional RFC3339 lower observation bound")
	notAfterValue := flags.String("not-after", "", "optional RFC3339 upper observation bound")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 0 || *file == "" || *actor == "" || *target == "" || *policy == "" || *nonce == "" {
		return usageError("usage: attacknet evidence verify-signer-report --file PATH --actor NAME --target NAME --policy-digest SHA256 --nonce VALUE [--key-id SHA256] [--not-before RFC3339] [--not-after RFC3339]")
	}
	notBefore, err := optionalTime(*notBeforeValue, "--not-before")
	if err != nil {
		return commandUsageError{err.Error()}
	}
	notAfter, err := optionalTime(*notAfterValue, "--not-after")
	if err != nil {
		return commandUsageError{err.Error()}
	}
	source, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("read signed report: %w", err)
	}
	verified, err := probeattribution.Verify(source, probeattribution.Expectation{
		Actor: *actor, TargetActor: *target, PolicyDigest: *policy,
		Nonce: *nonce, KeyID: *keyID, NotBefore: notBefore, NotAfter: notAfter,
	})
	if err != nil {
		return fmt.Errorf("verify signed report: %w", err)
	}
	result := SignerReportVerification{
		SchemaVersion: "stacks-attacknet-signer-report-verification/v1",
		Outcome:       "Verified", PayloadDigest: verified.PayloadDigest,
		KeyID:      verified.Response.Attestation.KeyID,
		ObservedAt: verified.Response.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	return json.NewEncoder(app.Stdout).Encode(result)
}
