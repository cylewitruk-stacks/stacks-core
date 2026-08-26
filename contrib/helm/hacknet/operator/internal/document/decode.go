// Package document decodes human-authored YAML or JSON into closed Go types.
package document

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

const maximumDocumentBytes = 8 << 20

// DecodeOne strictly decodes exactly one non-empty YAML or JSON document.
func DecodeOne(data []byte, target any) error {
	if target == nil {
		return errors.New("decode target is required")
	}
	if len(data) == 0 || len(data) > maximumDocumentBytes {
		return fmt.Errorf("document size must be within 1..%d bytes", maximumDocumentBytes)
	}
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var document []byte
	for {
		value, err := reader.Read()
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read YAML document: %w", err)
		}
		if len(bytes.TrimSpace(value)) > 0 {
			if document != nil {
				return errors.New("exactly one YAML or JSON document is required")
			}
			document = value
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if document == nil {
		return errors.New("document is empty")
	}
	// This pass is intentionally map-shaped: it detects duplicate YAML and JSON
	// keys before conversion could silently collapse them.
	var structural any
	if err := yaml.UnmarshalStrict(document, &structural); err != nil {
		return fmt.Errorf("invalid YAML or JSON structure: %w", err)
	}
	if structural == nil {
		return errors.New("document is empty")
	}
	encoded, err := yaml.YAMLToJSON(document)
	if err != nil {
		return fmt.Errorf("normalize YAML or JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode typed document: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing content: %w", err)
	}
	return errors.New("document contains trailing JSON values")
}

// EncodeYAML serializes one typed API object for human authoring.
func EncodeYAML(value any) ([]byte, error) {
	encoded, err := yaml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode YAML: %w", err)
	}
	return encoded, nil
}
