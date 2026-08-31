package attacknetcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedReportFixture(t *testing.T) (string, []string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(publicDER)
	keyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	nonce := "0123456789abcdef0123456789abcdef"
	policy := "sha256:" + strings.Repeat("a", 64)
	unsigned := map[string]any{
		"schemaVersion": "stacks-attacknet-probe-response/v1", "actor": "signer-1-observer",
		"kind": "signerBehavior", "nonce": nonce, "observedAt": "2026-08-30T12:00:00Z",
		"targetActor": "signer-1", "policyDigest": policy,
		"observation": map[string]any{"probe": "signer-behavior", "policyMatches": 1},
	}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{}
	for key, value := range unsigned {
		report[key] = value
	}
	report["attestation"] = map[string]any{
		"schemaVersion": "stacks-attacknet-probe-attestation/v1", "algorithm": "Ed25519",
		"keyId": keyID, "publicKey": base64.StdEncoding.EncodeToString(publicDER),
		"signedPayload": base64.StdEncoding.EncodeToString(payload),
		"signature":     base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, []string{"evidence", "verify-signer-report", "--file", path,
		"--actor", "signer-1-observer", "--target", "signer-1",
		"--policy-digest", policy, "--nonce", nonce, "--key-id", keyID}
}

func TestEvidenceVerifySignerReportAcceptsAuthenticReport(t *testing.T) {
	_, args := signedReportFixture(t)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "default", bytes.NewReader(nil), stdout, stderr)
	if code := app.Run(context.Background(), args); code != 0 {
		t.Fatalf("verification failed (%d): %s", code, stderr.String())
	}
	var result SignerReportVerification
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Verified" || result.ObservedAt != time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano) {
		t.Fatalf("unexpected verification: %#v", result)
	}
}

func TestEvidenceVerifySignerReportRejectsForgery(t *testing.T) {
	path, args := signedReportFixture(t)
	var report map[string]any
	encoded, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(encoded, &report) != nil {
		t.Fatal("read report fixture")
	}
	report["observation"].(map[string]any)["policyMatches"] = float64(2)
	encoded, _ = json.Marshal(report)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(nil, "default", bytes.NewReader(nil), stdout, stderr)
	if code := app.Run(context.Background(), args); code == 0 || !strings.Contains(stderr.String(), "signed probe payload differs") {
		t.Fatalf("forged report was not rejected (%d): %s", code, stderr.String())
	}
}
