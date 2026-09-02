// Command compile-check exposes the production fault compiler for deterministic
// cross-runtime contract tests.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fault"
)

type request struct {
	Cases []compileRequest `json:"cases"`
}

type compileRequest struct {
	Campaign attacknetv1alpha1.FaultCampaign `json:"campaign"`
	Manifest manifestInput                   `json:"manifest"`
}

type manifestInput struct {
	Network   string       `json:"network"`
	Namespace string       `json:"namespace"`
	Actors    []actorInput `json:"actors"`
}

type actorInput struct {
	Service      string   `json:"service"`
	Role         string   `json:"role"`
	SignerIndex  *int32   `json:"signerIndex,omitempty"`
	SignerWeight *float64 `json:"signerWeight,omitempty"`
}

type compileResponse struct {
	Resource map[string]any `json:"resource"`
	Evidence fault.Evidence `json:"evidence"`
}

type response struct {
	Cases []compileResponse `json:"cases"`
}

func main() {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	input := request{}
	if err := decoder.Decode(&input); err != nil {
		fatal(fmt.Errorf("decode request: %w", err))
	}
	if err := requireEOF(decoder); err != nil {
		fatal(err)
	}
	if len(input.Cases) == 0 || len(input.Cases) > 64 {
		fatal(fmt.Errorf("request cases must contain 1..64 entries"))
	}
	output := response{Cases: make([]compileResponse, len(input.Cases))}
	for caseIndex := range input.Cases {
		compileInput := &input.Cases[caseIndex]
		actors := make([]fault.ManifestActor, len(compileInput.Manifest.Actors))
		for actorIndex := range compileInput.Manifest.Actors {
			actor := &compileInput.Manifest.Actors[actorIndex]
			actors[actorIndex] = fault.ManifestActor{
				Name: actor.Service, Role: actor.Role,
				SignerIndex: actor.SignerIndex, SignerWeight: actor.SignerWeight,
			}
		}
		compiled, err := fault.Compile(&compileInput.Campaign, fault.Manifest{
			Network: compileInput.Manifest.Network, Namespace: compileInput.Manifest.Namespace, Actors: actors,
		})
		if err != nil {
			fatal(fmt.Errorf("compile case %d: %w", caseIndex, err))
		}
		output.Cases[caseIndex] = compileResponse{Resource: compiled.Resource.Object, Evidence: compiled.Evidence}
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fatal(fmt.Errorf("encode response: %w", err))
	}
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request contains trailing JSON")
		}
		return fmt.Errorf("decode trailing request data: %w", err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
