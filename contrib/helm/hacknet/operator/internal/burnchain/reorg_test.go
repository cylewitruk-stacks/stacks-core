package burnchain

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestPrepareAndExecuteReorgProvesHigherWorkReplacement(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	request := ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "bcrt1qattacknet"}
	prepared, err := PrepareReorg(context.Background(), bitcoin, request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ForkParent.Height != 4 || len(prepared.OriginalBranch) != 2 || prepared.Digest == "" {
		t.Fatalf("unexpected preparation: %#v", prepared)
	}
	result, err := ExecuteReorg(context.Background(), bitcoin, prepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CanonicalProven || result.Final.BestBlockHash != "replacement-3" || len(result.ReplacementBranch) != 3 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if bitcoin.invalidated {
		t.Fatal("reconsiderblock marker was not removed")
	}
}

func TestExecuteReorgRefusesStaleApprovalWithoutMutation(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	prepared, err := PrepareReorg(context.Background(), bitcoin, ReorgRequest{Depth: 1, ReplacementBlocks: 2, Wallet: "miner", Address: "address"})
	if err != nil {
		t.Fatal(err)
	}
	bitcoin.original = append(bitcoin.original, fakeHeader("original-7", 7))
	_, err = ExecuteReorg(context.Background(), bitcoin, prepared, nil)
	if err == nil || bitcoin.invalidateCalls != 0 {
		t.Fatalf("stale approval result = %v; invalidations = %d", err, bitcoin.invalidateCalls)
	}
}

func TestReorgRejectsBrokenBranchAncestry(t *testing.T) {
	t.Parallel()
	brokenOriginal := newFakeReorgBitcoin(6)
	brokenOriginal.badPreviousFor = "original-5"
	if _, err := PrepareReorg(context.Background(), brokenOriginal, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address"}); err == nil {
		t.Fatal("preparation accepted an original branch with broken ancestry")
	}
	brokenReplacement := newFakeReorgBitcoin(6)
	prepared, err := PrepareReorg(context.Background(), brokenReplacement, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address"})
	if err != nil {
		t.Fatal(err)
	}
	brokenReplacement.badPreviousFor = "replacement-1"
	result, err := ExecuteReorg(context.Background(), brokenReplacement, prepared, nil)
	if err == nil || !result.CleanupSucceeded || result.CanonicalProven {
		t.Fatalf("replacement with broken ancestry was not rejected and reconciled: %#v %v", result, err)
	}
}

func TestExecuteReorgDoesNotTreatReconsiderationAsCanonicalProof(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	bitcoin.forceOriginalAfterReconsider = true
	prepared, err := PrepareReorg(context.Background(), bitcoin, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecuteReorg(context.Background(), bitcoin, prepared, nil)
	if err == nil || result.CanonicalProven {
		t.Fatalf("false canonical proof: result=%#v err=%v", result, err)
	}
}

func TestExecuteReorgAttemptsCleanupAfterPartialFailure(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	bitcoin.failGenerationAt = 2
	prepared, err := PrepareReorg(context.Background(), bitcoin, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address", ReplacementInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecuteReorg(context.Background(), bitcoin, prepared, func(context.Context, time.Duration) error { return nil })
	if err == nil || !result.CleanupAttempted || !result.CleanupSucceeded || bitcoin.invalidated || result.Final.BestBlockHash != prepared.Original.BestBlockHash ||
		len(result.Receipts) != 4 || result.Receipts[2].Method != "generatetoaddress" || result.Receipts[2].Outcome != "uncertain" {
		t.Fatalf("partial cleanup result=%#v err=%v", result, err)
	}
}

func TestExecuteReorgRecordsUncertainInvalidationAndObservedCleanup(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	bitcoin.failInvalidateAfterMutation = true
	prepared, err := PrepareReorg(context.Background(), bitcoin, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecuteReorg(context.Background(), bitcoin, prepared, nil)
	if err == nil || !result.CleanupSucceeded || result.Final.BestBlockHash != prepared.Original.BestBlockHash ||
		len(result.Receipts) != 2 || result.Receipts[0].Outcome != "uncertain" || result.Receipts[1].Method != "reconsiderblock" {
		t.Fatalf("uncertain invalidation was not reconciled: result=%#v err=%v", result, err)
	}
}

func TestExecuteReorgDoesNotClaimCleanupWhenPartialBranchWins(t *testing.T) {
	t.Parallel()
	bitcoin := newFakeReorgBitcoin(6)
	bitcoin.failHeaderFor = "replacement-3"
	prepared, err := PrepareReorg(context.Background(), bitcoin, ReorgRequest{Depth: 2, ReplacementBlocks: 3, Wallet: "miner", Address: "address"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecuteReorg(context.Background(), bitcoin, prepared, nil)
	if err == nil || !result.CleanupAttempted || result.CleanupSucceeded || result.Final.BestBlockHash != "replacement-3" || result.CleanupFailure == "" {
		t.Fatalf("higher-work partial branch was misreported as restored: result=%#v err=%v", result, err)
	}
}

func TestMaximumReorgEvidenceFitsBoundedCampaignStatus(t *testing.T) {
	t.Parallel()
	result := ReorgResult{
		SchemaVersion:   "attacknet-burnchain-reorg-result/v1",
		PreparedDigest:  fmt.Sprintf("sha256:%064x", 1),
		Original:        ChainInfo{Chain: "regtest", Blocks: 10_000, BestBlockHash: fmt.Sprintf("%064x", 2), Chainwork: fmt.Sprintf("%064x", 10_001)},
		ForkParent:      BlockHeader{Hash: fmt.Sprintf("%064x", 3), Height: 9_856, Chainwork: fmt.Sprintf("%064x", 9_857)},
		Final:           ChainInfo{Chain: "regtest", Blocks: 10_144, BestBlockHash: fmt.Sprintf("%064x", 4), Chainwork: fmt.Sprintf("%064x", 10_145)},
		CanonicalProven: true,
	}
	for index := 0; index < 144; index++ {
		result.OriginalBranch = append(result.OriginalBranch, realisticHeader(index+10))
	}
	for index := 0; index < 288; index++ {
		header := realisticHeader(index + 1_000)
		result.ReplacementBranch = append(result.ReplacementBranch, header)
		result.Receipts = append(result.Receipts, RPCReceipt{Sequence: int32(index + 2), Method: "generatetoaddress", Hashes: []string{header.Hash}, Outcome: "acknowledged"})
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 512<<10 {
		t.Fatalf("maximum reorg evidence is %d bytes, want at most 512 KiB", len(encoded))
	}
}

func realisticHeader(index int) BlockHeader {
	return BlockHeader{
		Hash: fmt.Sprintf("%064x", index), Height: int64(index),
		PreviousHash: fmt.Sprintf("%064x", index-1), Chainwork: fmt.Sprintf("%064x", index+1), Confirmations: 1,
	}
}

type fakeReorgBitcoin struct {
	original                     []BlockHeader
	replacement                  []BlockHeader
	invalidated                  bool
	invalidateCalls              int
	failGenerationAt             int
	failInvalidateAfterMutation  bool
	failHeaderFor                string
	badPreviousFor               string
	forceOriginalAfterReconsider bool
	forkHeight                   int64
}

func newFakeReorgBitcoin(height int64) *fakeReorgBitcoin {
	result := &fakeReorgBitcoin{}
	for index := int64(0); index <= height; index++ {
		result.original = append(result.original, fakeHeader(fmt.Sprintf("original-%d", index), index))
	}
	return result
}

func fakeHeader(hash string, height int64) BlockHeader {
	previous := ""
	if height > 0 {
		previous = fmt.Sprintf("original-%d", height-1)
	}
	return BlockHeader{Hash: hash, Height: height, PreviousHash: previous, Chainwork: fmt.Sprintf("%x", height+1), Confirmations: 1}
}

func (bitcoin *fakeReorgBitcoin) active() []BlockHeader {
	if bitcoin.invalidated || (len(bitcoin.replacement) > 0 && !bitcoin.forceOriginalAfterReconsider && len(bitcoin.replacement) > len(bitcoin.original)-int(bitcoin.replacement[0].Height)) {
		if len(bitcoin.replacement) == 0 {
			return bitcoin.original[:bitcoin.forkHeight+1]
		}
		forkHeight := bitcoin.replacement[0].Height - 1
		return append(append([]BlockHeader(nil), bitcoin.original[:forkHeight+1]...), bitcoin.replacement...)
	}
	return bitcoin.original
}

func (bitcoin *fakeReorgBitcoin) ChainInfo(context.Context) (ChainInfo, error) {
	active := bitcoin.active()
	tip := active[len(active)-1]
	return ChainInfo{Chain: "regtest", Blocks: tip.Height, Headers: tip.Height, BestBlockHash: tip.Hash, Chainwork: tip.Chainwork}, nil
}

func (bitcoin *fakeReorgBitcoin) BlockHash(_ context.Context, height int64) (string, error) {
	active := bitcoin.active()
	if height < 0 || height >= int64(len(active)) {
		return "", fmt.Errorf("height %d unavailable", height)
	}
	return active[height].Hash, nil
}

func (bitcoin *fakeReorgBitcoin) BlockHeader(_ context.Context, hash string) (BlockHeader, error) {
	if hash == bitcoin.failHeaderFor {
		return BlockHeader{}, fmt.Errorf("injected header failure for %s", hash)
	}
	for _, header := range append(append([]BlockHeader(nil), bitcoin.original...), bitcoin.replacement...) {
		if header.Hash == hash {
			if hash == bitcoin.badPreviousFor {
				header.PreviousHash = "wrong-parent"
			}
			return header, nil
		}
	}
	return BlockHeader{}, fmt.Errorf("unknown block %s", hash)
}

func (bitcoin *fakeReorgBitcoin) ChainTips(context.Context) ([]ChainTip, error) {
	info, _ := bitcoin.ChainInfo(context.Background())
	return []ChainTip{{Height: info.Blocks, Hash: info.BestBlockHash, Status: "active"}}, nil
}

func (bitcoin *fakeReorgBitcoin) InvalidateBlock(_ context.Context, hash string) error {
	bitcoin.invalidateCalls++
	for index, header := range bitcoin.original {
		if header.Hash == hash {
			bitcoin.invalidated = true
			bitcoin.replacement = nil
			bitcoin.forkHeight = int64(index - 1)
			if bitcoin.failInvalidateAfterMutation {
				return fmt.Errorf("injected response loss after invalidation")
			}
			return nil
		}
	}
	return fmt.Errorf("unknown block %s", hash)
}

func (bitcoin *fakeReorgBitcoin) ReconsiderBlock(context.Context, string) error {
	bitcoin.invalidated = false
	return nil
}

func (bitcoin *fakeReorgBitcoin) GenerateBlocks(_ context.Context, _, _ string, count int32) ([]string, error) {
	if count != 1 {
		return nil, fmt.Errorf("unexpected count %d", count)
	}
	if bitcoin.failGenerationAt > 0 && len(bitcoin.replacement)+1 == bitcoin.failGenerationAt {
		return nil, fmt.Errorf("injected generation failure")
	}
	height := bitcoin.forkHeight + int64(len(bitcoin.replacement)) + 1
	hash := fmt.Sprintf("replacement-%d", len(bitcoin.replacement)+1)
	header := BlockHeader{Hash: hash, Height: height, Chainwork: fmt.Sprintf("%x", height+1), Confirmations: 1}
	if len(bitcoin.replacement) > 0 {
		header.PreviousHash = bitcoin.replacement[len(bitcoin.replacement)-1].Hash
	} else {
		header.PreviousHash = bitcoin.original[height-1].Hash
	}
	bitcoin.replacement = append(bitcoin.replacement, header)
	return []string{hash}, nil
}
