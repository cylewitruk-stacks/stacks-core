package burnchain

import (
	"errors"
	"fmt"
	"os"
)

// PolicySource loads the latest desired burnchain policy.
type PolicySource interface {
	Load() (Policy, error)
}

// FilePolicySource reads a kubelet-projected policy file.
type FilePolicySource struct {
	// Path is the kubelet-projected policy file.
	Path string
	// Defaults define bounded values omitted by an older projection.
	Defaults PolicyDefaults
}

// Load reads the current policy, falling back only when the projection does not yet exist.
func (source FilePolicySource) Load() (Policy, error) {
	file, err := os.Open(source.Path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultPolicy(source.Defaults), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("open policy: %w", err)
	}
	defer file.Close()
	return ParsePolicy(file, source.Defaults)
}
