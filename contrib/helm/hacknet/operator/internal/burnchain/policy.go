// Package burnchain implements the Stacks-blind Bitcoin regtest clock.
package burnchain

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxPolicyBytes = 64 << 10

// Mode controls continuous block production.
type Mode string

const (
	// ModeRun mines continuously at the configured cadence.
	ModeRun Mode = "run"
	// ModePause mines only an admitted burst or an explicit one-block request.
	ModePause Mode = "pause"
)

// AddressMode controls how mining destinations are selected.
type AddressMode string

const (
	// AddressRoundRobin rotates across every configured miner address.
	AddressRoundRobin AddressMode = "round-robin"
	// AddressFixed always selects one configured miner address.
	AddressFixed AddressMode = "fixed"
)

// Policy is one immutable generation of burnchain-clock behavior.
type Policy struct {
	// Generation is the monotonic immutable policy identity.
	Generation uint64
	// Mode selects continuous or explicitly requested mining.
	Mode Mode
	// IntervalSeconds is the base delay between blocks.
	IntervalSeconds uint64
	// JitterSeconds is the inclusive deterministic jitter bound.
	JitterSeconds uint64
	// BurstBlocks is the restart-unsafe compatibility count used without a target.
	BurstBlocks uint64
	// BurstTargetHeight is the idempotent desired height for a bounded burst.
	BurstTargetHeight uint64
	// AddressMode selects round-robin or fixed mining destinations.
	AddressMode AddressMode
	// FixedAddressIndex selects the destination when AddressMode is fixed.
	FixedAddressIndex uint64
}

// PolicyDefaults supplies values omitted from the projected policy file.
type PolicyDefaults struct {
	// IntervalSeconds is used when INTERVAL_SECONDS is omitted.
	IntervalSeconds uint64
	// MaxDelaySeconds bounds both interval and jitter.
	MaxDelaySeconds uint64
}

// DefaultPolicy returns the policy used when no projected file exists yet.
func DefaultPolicy(defaults PolicyDefaults) Policy {
	return Policy{
		Mode:            ModeRun,
		IntervalSeconds: defaults.IntervalSeconds,
		AddressMode:     AddressRoundRobin,
	}
}

// ParsePolicy decodes the bounded KEY=value projection consumed by the clock.
func ParsePolicy(reader io.Reader, defaults PolicyDefaults) (Policy, error) {
	if defaults.MaxDelaySeconds == 0 {
		return Policy{}, fmt.Errorf("maximum delay must be positive")
	}
	contents, err := io.ReadAll(io.LimitReader(reader, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if len(contents) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("policy exceeds %d bytes", maxPolicyBytes)
	}
	policy := DefaultPolicy(defaults)
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return Policy{}, fmt.Errorf("invalid policy line %q", line)
		}
		if seen[key] {
			return Policy{}, fmt.Errorf("duplicate policy key %q", key)
		}
		seen[key] = true
		var err error
		switch key {
		case "GENERATION":
			policy.Generation, err = parseUint(key, value)
		case "MODE":
			policy.Mode = Mode(value)
		case "INTERVAL_SECONDS":
			policy.IntervalSeconds, err = parseUint(key, value)
		case "JITTER_SECONDS":
			policy.JitterSeconds, err = parseUint(key, value)
		case "BURST_BLOCKS":
			policy.BurstBlocks, err = parseUint(key, value)
		case "BURST_TARGET_HEIGHT":
			policy.BurstTargetHeight, err = parseUint(key, value)
		case "ADDRESS_MODE":
			policy.AddressMode = AddressMode(value)
		case "FIXED_ADDRESS_INDEX":
			policy.FixedAddressIndex, err = parseUint(key, value)
		default:
			return Policy{}, fmt.Errorf("unknown policy key %q", key)
		}
		if err != nil {
			return Policy{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if policy.Mode != ModeRun && policy.Mode != ModePause {
		return Policy{}, fmt.Errorf("unsupported policy mode %q", policy.Mode)
	}
	if policy.AddressMode != AddressRoundRobin && policy.AddressMode != AddressFixed {
		return Policy{}, fmt.Errorf("unsupported address mode %q", policy.AddressMode)
	}
	if policy.IntervalSeconds > defaults.MaxDelaySeconds {
		return Policy{}, fmt.Errorf("interval %d exceeds maximum %d", policy.IntervalSeconds, defaults.MaxDelaySeconds)
	}
	if policy.JitterSeconds > defaults.MaxDelaySeconds {
		return Policy{}, fmt.Errorf("jitter %d exceeds maximum %d", policy.JitterSeconds, defaults.MaxDelaySeconds)
	}
	return policy, nil
}

// EncodePolicy renders the stable projection format used by ConfigMaps.
func EncodePolicy(policy Policy) string {
	return fmt.Sprintf("GENERATION=%d\nMODE=%s\nINTERVAL_SECONDS=%d\nJITTER_SECONDS=%d\nBURST_BLOCKS=%d\nBURST_TARGET_HEIGHT=%d\nADDRESS_MODE=%s\nFIXED_ADDRESS_INDEX=%d\n",
		policy.Generation, policy.Mode, policy.IntervalSeconds, policy.JitterSeconds,
		policy.BurstBlocks, policy.BurstTargetHeight, policy.AddressMode, policy.FixedAddressIndex)
}

func parseUint(key, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer: %w", key, err)
	}
	return parsed, nil
}
