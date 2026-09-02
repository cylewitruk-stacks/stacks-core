// Package probeattribution verifies signed reports from isolated observation actors.
package probeattribution

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const (
	// ResponseSchema is the signed probe response contract.
	ResponseSchema = "stacks-attacknet-probe-response/v1"
	// AttestationSchema is the observer signature contract.
	AttestationSchema   = "stacks-attacknet-probe-attestation/v1"
	maximumPayloadBytes = 64 * 1024
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// Attestation carries the exact signed payload and observer public key.
type Attestation struct {
	SchemaVersion string `json:"schemaVersion"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	PublicKey     string `json:"publicKey"`
	SignedPayload string `json:"signedPayload"`
	Signature     string `json:"signature"`
}

// Response is the bounded outer probe response used by controller gates.
type Response struct {
	SchemaVersion string          `json:"schemaVersion"`
	Actor         string          `json:"actor"`
	Kind          string          `json:"kind"`
	Nonce         string          `json:"nonce"`
	ObservedAt    time.Time       `json:"observedAt"`
	TargetActor   string          `json:"targetActor"`
	PolicyDigest  string          `json:"policyDigest"`
	Observation   json.RawMessage `json:"observation"`
	Attestation   Attestation     `json:"attestation"`
}

// Expectation binds a report to one admitted observer and target contract.
type Expectation struct {
	Actor        string
	TargetActor  string
	PolicyDigest string
	Nonce        string
	KeyID        string
	NotBefore    time.Time
	NotAfter     time.Time
}

// Verified is the identity-bound report after signature and envelope checks.
type Verified struct {
	Response      Response
	PayloadDigest string
}

// Verify authenticates and binds one observer report.
func Verify(source []byte, expected Expectation) (Verified, error) {
	if len(source) == 0 || len(source) > maximumPayloadBytes {
		return Verified{}, fmt.Errorf("probe response must contain 1..%d bytes", maximumPayloadBytes)
	}
	var response Response
	if err := json.Unmarshal(source, &response); err != nil {
		return Verified{}, fmt.Errorf("decode probe response: %w", err)
	}
	if response.SchemaVersion != ResponseSchema || response.Attestation.SchemaVersion != AttestationSchema || response.Attestation.Algorithm != "Ed25519" {
		return Verified{}, errors.New("unsupported probe response or attestation contract")
	}
	if !noncePattern.MatchString(expected.Nonce) || response.Nonce != expected.Nonce {
		return Verified{}, errors.New("probe response nonce does not match the controller challenge")
	}
	if response.Actor != expected.Actor || response.TargetActor != expected.TargetActor || response.PolicyDigest != expected.PolicyDigest {
		return Verified{}, errors.New("probe response identity or policy binding does not match")
	}
	if (!expected.NotBefore.IsZero() && response.ObservedAt.Before(expected.NotBefore)) ||
		(!expected.NotAfter.IsZero() && response.ObservedAt.After(expected.NotAfter)) {
		return Verified{}, errors.New("probe response is outside the admitted observation window")
	}
	publicBytes, err := base64.StdEncoding.DecodeString(response.Attestation.PublicKey)
	if err != nil {
		return Verified{}, errors.New("probe public key is not valid base64")
	}
	keyID := sha256.Sum256(publicBytes)
	wantKeyID := "sha256:" + hex.EncodeToString(keyID[:])
	if response.Attestation.KeyID != wantKeyID || expected.KeyID != "" && expected.KeyID != wantKeyID {
		return Verified{}, errors.New("probe public-key identity does not match")
	}
	parsed, err := x509.ParsePKIXPublicKey(publicBytes)
	if err != nil {
		return Verified{}, fmt.Errorf("parse probe public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return Verified{}, errors.New("probe public key is not Ed25519")
	}
	payload, err := base64.StdEncoding.DecodeString(response.Attestation.SignedPayload)
	if err != nil || len(payload) == 0 || len(payload) > maximumPayloadBytes {
		return Verified{}, errors.New("probe signed payload is malformed or unbounded")
	}
	signature, err := base64.StdEncoding.DecodeString(response.Attestation.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return Verified{}, errors.New("probe response signature is invalid")
	}
	var signed map[string]any
	if err := json.Unmarshal(payload, &signed); err != nil {
		return Verified{}, errors.New("probe signed payload is not JSON")
	}
	unsigned := map[string]any{}
	if err := json.Unmarshal(source, &unsigned); err != nil {
		return Verified{}, err
	}
	delete(unsigned, "attestation")
	signedDigest, err := canonical.Digest(signed)
	if err != nil {
		return Verified{}, fmt.Errorf("digest signed probe payload: %w", err)
	}
	unsignedDigest, err := canonical.Digest(unsigned)
	if err != nil {
		return Verified{}, fmt.Errorf("digest probe response envelope: %w", err)
	}
	if signedDigest != unsignedDigest {
		return Verified{}, errors.New("signed probe payload differs from the response envelope")
	}
	return Verified{Response: response, PayloadDigest: signedDigest}, nil
}
