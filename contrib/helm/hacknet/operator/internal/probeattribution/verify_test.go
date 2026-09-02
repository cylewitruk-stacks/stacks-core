package probeattribution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func signedResponse(t *testing.T) ([]byte, Expectation) {
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
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	payload := map[string]any{
		"schemaVersion": ResponseSchema, "actor": "signer-1-observer",
		"kind": "network", "nonce": "qualified-nonce-001", "observedAt": now.Format(time.RFC3339),
		"targetActor": "signer-1", "policyDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"observation": map[string]any{"successes": float64(3)},
	}
	signed, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["attestation"] = map[string]any{
		"schemaVersion": AttestationSchema, "algorithm": "Ed25519", "keyId": keyID,
		"publicKey":     base64.StdEncoding.EncodeToString(publicDER),
		"signedPayload": base64.StdEncoding.EncodeToString(signed),
		"signature":     base64.StdEncoding.EncodeToString(ed25519.Sign(private, signed)),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, Expectation{
		Actor: "signer-1-observer", TargetActor: "signer-1",
		PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Nonce:        "qualified-nonce-001", KeyID: keyID,
		NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Second),
	}
}

func TestVerifyBindsSignedReport(t *testing.T) {
	source, expected := signedResponse(t)
	verified, err := Verify(source, expected)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PayloadDigest == "" || verified.Response.Actor != expected.Actor {
		t.Fatalf("report not verified: %#v", verified)
	}
}

func TestVerifyRejectsTamperingReplayAndIdentityDrift(t *testing.T) {
	source, expected := signedResponse(t)
	var envelope map[string]any
	if err := json.Unmarshal(source, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["targetActor"] = "signer-2"
	tampered, _ := json.Marshal(envelope)
	if _, err := Verify(tampered, expected); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
	if replay := expected; true {
		replay.Nonce = "different-nonce-01"
		if _, err := Verify(source, replay); err == nil {
			t.Fatal("replayed nonce was accepted")
		}
	}
	if drift := expected; true {
		drift.KeyID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		if _, err := Verify(source, drift); err == nil {
			t.Fatal("observer key drift was accepted")
		}
	}
}
