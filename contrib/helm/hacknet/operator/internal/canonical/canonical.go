// Package canonical provides deterministic JSON artifact encoding and hashing.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
)

// Marshal returns compact JSON with recursively sorted object keys.
func Marshal(value any) ([]byte, error) {
	intermediate, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical input: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(intermediate))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode canonical input: %w", err)
	}
	if err := validate(normalized, "$"); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON: %w", err)
	}
	return encoded, nil
}

// Digest returns the versioned SHA-256 digest of canonical JSON.
func Digest(value any) (string, error) {
	encoded, err := Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ArtifactDigest hashes ordinary Go JSON, including finite floating-point values.
// It is for Go-owned artifacts; cross-runtime inventory bindings must use Digest.
func ArtifactDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal artifact: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Decode parses bounded arbitrary JSON while retaining exact integer spelling.
func Decode(data []byte, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(data), int64(len(data))+1))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func validate(value any, path string) error {
	switch typed := value.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		integer, err := typed.Int64()
		if err != nil {
			return fmt.Errorf("%s must contain integers only: %w", path, err)
		}
		if math.Abs(float64(integer)) > 9_007_199_254_740_991 {
			return fmt.Errorf("%s exceeds the JSON safe-integer range", path)
		}
		return nil
	case []any:
		for index, item := range typed {
			if err := validate(item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for key, item := range typed {
			if err := validate(item, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s contains unsupported canonical JSON type %T", path, value)
	}
}
