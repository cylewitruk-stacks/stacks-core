package burnchain

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

// ReorgBitcoin is the finite RPC surface available to the reorg engine.
type ReorgBitcoin interface {
	ChainInfo(context.Context) (ChainInfo, error)
	BlockHash(context.Context, int64) (string, error)
	BlockHeader(context.Context, string) (BlockHeader, error)
	ChainTips(context.Context) ([]ChainTip, error)
	InvalidateBlock(context.Context, string) error
	ReconsiderBlock(context.Context, string) error
	GenerateBlocks(context.Context, string, string, int32) ([]string, error)
}

// ReorgRequest is the bounded input accepted by the semantic worker.
type ReorgRequest struct {
	Depth               int32         `json:"depth"`
	ReplacementBlocks   int32         `json:"replacementBlocks"`
	ReplacementInterval time.Duration `json:"replacementIntervalNanoseconds"`
	Wallet              string        `json:"wallet"`
	Address             string        `json:"address"`
}

// PreparedReorg binds approval to one exact canonical Bitcoin branch.
type PreparedReorg struct {
	SchemaVersion  string        `json:"schemaVersion"`
	Request        ReorgRequest  `json:"request"`
	Original       ChainInfo     `json:"original"`
	ForkParent     BlockHeader   `json:"forkParent"`
	OriginalBranch []BlockHeader `json:"originalBranch"`
	ChainTips      []ChainTip    `json:"chainTips"`
	Digest         string        `json:"digest"`
}

// RPCReceipt records one bounded mutation or verification operation.
type RPCReceipt struct {
	Sequence int32    `json:"sequence"`
	Method   string   `json:"method"`
	Block    string   `json:"block,omitempty"`
	Hashes   []string `json:"hashes,omitempty"`
	Outcome  string   `json:"outcome"`
}

// ReorgResult is the complete branch proof retained by the campaign.
type ReorgResult struct {
	SchemaVersion     string        `json:"schemaVersion"`
	PreparedDigest    string        `json:"preparedDigest"`
	Original          ChainInfo     `json:"original"`
	ForkParent        BlockHeader   `json:"forkParent"`
	OriginalBranch    []BlockHeader `json:"originalBranch"`
	ReplacementBranch []BlockHeader `json:"replacementBranch,omitempty"`
	Final             ChainInfo     `json:"final"`
	FinalTips         []ChainTip    `json:"finalTips,omitempty"`
	Receipts          []RPCReceipt  `json:"receipts"`
	CanonicalProven   bool          `json:"canonicalProven"`
	CleanupAttempted  bool          `json:"cleanupAttempted,omitempty"`
	CleanupSucceeded  bool          `json:"cleanupSucceeded,omitempty"`
	CleanupFailure    string        `json:"cleanupFailure,omitempty"`
	Failure           string        `json:"failure,omitempty"`
}

// PrepareReorg captures the exact suffix that execution may replace.
func PrepareReorg(ctx context.Context, bitcoin ReorgBitcoin, request ReorgRequest) (PreparedReorg, error) {
	if err := validateReorgRequest(request); err != nil {
		return PreparedReorg{}, err
	}
	info, err := bitcoin.ChainInfo(ctx)
	if err != nil {
		return PreparedReorg{}, fmt.Errorf("read chain info: %w", err)
	}
	if info.Chain != "regtest" {
		return PreparedReorg{}, fmt.Errorf("refusing reorg on Bitcoin chain %q", info.Chain)
	}
	if info.Blocks < int64(request.Depth) {
		return PreparedReorg{}, fmt.Errorf("reorg depth %d exceeds tip height %d", request.Depth, info.Blocks)
	}
	forkHeight := info.Blocks - int64(request.Depth)
	forkHash, err := bitcoin.BlockHash(ctx, forkHeight)
	if err != nil {
		return PreparedReorg{}, fmt.Errorf("resolve fork parent at %d: %w", forkHeight, err)
	}
	forkParent, err := bitcoin.BlockHeader(ctx, forkHash)
	if err != nil {
		return PreparedReorg{}, fmt.Errorf("read fork parent %s: %w", forkHash, err)
	}
	if forkParent.Hash != forkHash || forkParent.Height != forkHeight {
		return PreparedReorg{}, errors.New("fork-parent header does not match its canonical height and hash")
	}
	branch := make([]BlockHeader, 0, request.Depth)
	parent := forkParent
	for height := forkHeight + 1; height <= info.Blocks; height++ {
		hash, hashErr := bitcoin.BlockHash(ctx, height)
		if hashErr != nil {
			return PreparedReorg{}, fmt.Errorf("resolve original branch height %d: %w", height, hashErr)
		}
		header, headerErr := bitcoin.BlockHeader(ctx, hash)
		if headerErr != nil {
			return PreparedReorg{}, fmt.Errorf("read original branch block %s: %w", hash, headerErr)
		}
		if err := validateBranchHeader(parent, header, hash, height); err != nil {
			return PreparedReorg{}, fmt.Errorf("validate original branch block %s: %w", hash, err)
		}
		branch = append(branch, header)
		parent = header
	}
	if len(branch) == 0 || branch[len(branch)-1].Hash != info.BestBlockHash || branch[len(branch)-1].Chainwork != info.Chainwork {
		return PreparedReorg{}, errors.New("captured branch does not terminate at the canonical tip")
	}
	tips, err := bitcoin.ChainTips(ctx)
	if err != nil {
		return PreparedReorg{}, fmt.Errorf("read chain tips: %w", err)
	}
	sortChainTips(tips)
	prepared := PreparedReorg{
		SchemaVersion: "attacknet-burnchain-reorg-prepared/v1", Request: request,
		Original: info, ForkParent: forkParent, OriginalBranch: branch, ChainTips: tips,
	}
	digest, err := canonical.ArtifactDigest(struct {
		SchemaVersion string        `json:"schemaVersion"`
		Request       ReorgRequest  `json:"request"`
		Original      ChainInfo     `json:"original"`
		ForkParent    BlockHeader   `json:"forkParent"`
		Branch        []BlockHeader `json:"originalBranch"`
	}{prepared.SchemaVersion, prepared.Request, prepared.Original, prepared.ForkParent, prepared.OriginalBranch})
	if err != nil {
		return PreparedReorg{}, err
	}
	prepared.Digest = digest
	return prepared, nil
}

// ExecuteReorg performs one approved replacement and proves final canonicality.
func ExecuteReorg(ctx context.Context, bitcoin ReorgBitcoin, prepared PreparedReorg, wait func(context.Context, time.Duration) error) (result ReorgResult, err error) {
	result = ReorgResult{
		SchemaVersion: "attacknet-burnchain-reorg-result/v1", PreparedDigest: prepared.Digest,
		Original: prepared.Original, ForkParent: prepared.ForkParent,
		OriginalBranch: append([]BlockHeader(nil), prepared.OriginalBranch...),
	}
	current, err := bitcoin.ChainInfo(ctx)
	if err != nil {
		return result, fmt.Errorf("re-read chain info: %w", err)
	}
	if current.BestBlockHash != prepared.Original.BestBlockHash || current.Blocks != prepared.Original.Blocks || current.Chainwork != prepared.Original.Chainwork {
		return result, errors.New("approved Bitcoin precondition is stale")
	}
	if len(prepared.OriginalBranch) == 0 {
		return result, errors.New("approved original branch is empty")
	}
	first := prepared.OriginalBranch[0].Hash
	sequence := int32(1)
	mutationAttempted, invalidityMarkerMayRemain := true, true
	defer func() {
		if err == nil || !mutationAttempted {
			return
		}
		result.Failure = err.Error()
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if invalidityMarkerMayRemain {
			result.CleanupAttempted = true
			sequence++
			cleanupErr := bitcoin.ReconsiderBlock(cleanupContext, first)
			outcome := "acknowledged"
			if cleanupErr != nil {
				outcome = "uncertain"
				result.CleanupFailure = fmt.Sprintf("remove original invalidity marker: %v", cleanupErr)
			}
			result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "reconsiderblock", Block: first, Outcome: outcome})
		}
		final, finalErr := bitcoin.ChainInfo(cleanupContext)
		if finalErr != nil {
			result.CleanupFailure = appendFailure(result.CleanupFailure, fmt.Sprintf("observe post-failure chain: %v", finalErr))
			return
		}
		result.Final = final
		tips, tipsErr := bitcoin.ChainTips(cleanupContext)
		if tipsErr != nil {
			result.CleanupFailure = appendFailure(result.CleanupFailure, fmt.Sprintf("observe post-failure tips: %v", tipsErr))
			return
		}
		sortChainTips(tips)
		result.FinalTips = tips
		result.CleanupSucceeded = result.CleanupAttempted &&
			final.BestBlockHash == prepared.Original.BestBlockHash &&
			final.Blocks == prepared.Original.Blocks && final.Chainwork == prepared.Original.Chainwork
		if result.CleanupAttempted && !result.CleanupSucceeded && result.CleanupFailure == "" {
			result.CleanupFailure = fmt.Sprintf("original branch was not restored; canonical tip is %s", final.BestBlockHash)
		}
	}()
	if invalidateErr := bitcoin.InvalidateBlock(ctx, first); invalidateErr != nil {
		result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "invalidateblock", Block: first, Outcome: "uncertain"})
		return result, fmt.Errorf("invalidate original branch %s: %w", first, invalidateErr)
	}
	result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "invalidateblock", Block: first, Outcome: "acknowledged"})
	afterInvalidate, err := bitcoin.ChainInfo(ctx)
	if err != nil {
		return result, fmt.Errorf("verify fork parent after invalidation: %w", err)
	}
	if afterInvalidate.BestBlockHash != prepared.ForkParent.Hash {
		return result, fmt.Errorf("invalidation selected %s, want fork parent %s", afterInvalidate.BestBlockHash, prepared.ForkParent.Hash)
	}
	for index := int32(0); index < prepared.Request.ReplacementBlocks; index++ {
		if index > 0 && prepared.Request.ReplacementInterval > 0 {
			if wait == nil {
				return result, errors.New("replacement interval requires a wait function")
			}
			if waitErr := wait(ctx, prepared.Request.ReplacementInterval); waitErr != nil {
				return result, waitErr
			}
		}
		sequence++
		hashes, generateErr := bitcoin.GenerateBlocks(ctx, prepared.Request.Wallet, prepared.Request.Address, 1)
		if generateErr != nil {
			result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "generatetoaddress", Outcome: "uncertain"})
			return result, fmt.Errorf("generate replacement block %d: %w", index+1, generateErr)
		}
		if len(hashes) != 1 || hashes[0] == "" {
			result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "generatetoaddress", Hashes: append([]string(nil), hashes...), Outcome: "uncertain"})
			return result, fmt.Errorf("generate replacement block %d returned %d usable hashes, want 1", index+1, len(hashes))
		}
		result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "generatetoaddress", Hashes: append([]string(nil), hashes...), Outcome: "acknowledged"})
		header, headerErr := bitcoin.BlockHeader(ctx, hashes[0])
		if headerErr != nil {
			return result, fmt.Errorf("read replacement header %s: %w", hashes[0], headerErr)
		}
		parent := prepared.ForkParent
		if len(result.ReplacementBranch) > 0 {
			parent = result.ReplacementBranch[len(result.ReplacementBranch)-1]
		}
		if err := validateBranchHeader(parent, header, hashes[0], prepared.ForkParent.Height+int64(index)+1); err != nil {
			return result, fmt.Errorf("validate replacement header %s: %w", hashes[0], err)
		}
		result.ReplacementBranch = append(result.ReplacementBranch, header)
	}
	sequence++
	if err := bitcoin.ReconsiderBlock(ctx, first); err != nil {
		result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "reconsiderblock", Block: first, Outcome: "uncertain"})
		return result, fmt.Errorf("reconsider original branch %s: %w", first, err)
	}
	invalidityMarkerMayRemain = false
	result.Receipts = append(result.Receipts, RPCReceipt{Sequence: sequence, Method: "reconsiderblock", Block: first, Outcome: "acknowledged"})
	result.Final, err = bitcoin.ChainInfo(ctx)
	if err != nil {
		return result, fmt.Errorf("read final chain info: %w", err)
	}
	result.FinalTips, err = bitcoin.ChainTips(ctx)
	if err != nil {
		return result, fmt.Errorf("read final chain tips: %w", err)
	}
	sortChainTips(result.FinalTips)
	expected := result.ReplacementBranch[len(result.ReplacementBranch)-1]
	higher, compareErr := greaterChainwork(result.Final.Chainwork, prepared.Original.Chainwork)
	if compareErr != nil {
		return result, compareErr
	}
	if result.Final.BestBlockHash != expected.Hash || result.Final.Blocks != expected.Height || result.Final.Chainwork != expected.Chainwork || !higher {
		return result, fmt.Errorf("replacement branch is not canonical: tip=%s expected=%s higherWork=%t", result.Final.BestBlockHash, expected.Hash, higher)
	}
	result.CanonicalProven = true
	return result, nil
}

func validateBranchHeader(parent, header BlockHeader, expectedHash string, expectedHeight int64) error {
	if header.Hash != expectedHash || header.Height != expectedHeight || header.PreviousHash != parent.Hash {
		return errors.New("header identity or ancestry does not match the expected branch")
	}
	higher, err := greaterChainwork(header.Chainwork, parent.Chainwork)
	if err != nil {
		return err
	}
	if !higher {
		return errors.New("header chainwork does not increase over its parent")
	}
	return nil
}

func appendFailure(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}

func validateReorgRequest(request ReorgRequest) error {
	if request.Depth < 1 || request.Depth > 144 {
		return errors.New("depth must be within 1..144")
	}
	if request.ReplacementBlocks <= request.Depth || request.ReplacementBlocks > 288 {
		return errors.New("replacementBlocks must exceed depth and not exceed 288")
	}
	if request.ReplacementInterval < 0 || request.ReplacementInterval > time.Hour {
		return errors.New("replacementInterval must be within 0..1h")
	}
	if request.Wallet == "" || request.Address == "" {
		return errors.New("wallet and address are required")
	}
	return nil
}

func greaterChainwork(left, right string) (bool, error) {
	leftValue, ok := new(big.Int).SetString(left, 16)
	if !ok {
		return false, fmt.Errorf("invalid final chainwork %q", left)
	}
	rightValue, ok := new(big.Int).SetString(right, 16)
	if !ok {
		return false, fmt.Errorf("invalid original chainwork %q", right)
	}
	return leftValue.Cmp(rightValue) > 0, nil
}

func sortChainTips(tips []ChainTip) {
	sort.Slice(tips, func(i, j int) bool {
		if tips[i].Height != tips[j].Height {
			return tips[i].Height > tips[j].Height
		}
		return tips[i].Hash < tips[j].Hash
	})
}
