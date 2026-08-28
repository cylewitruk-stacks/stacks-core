package burnchainworker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

func TestRunKeepsFailedStatusObservableUntilDeletion(t *testing.T) {
	t.Parallel()
	preparation := filepath.Join(t.TempDir(), "preparation")
	approval := filepath.Join(t.TempDir(), "approval")
	if err := os.WriteFile(preparation, []byte("sha256:paused-policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(approval, []byte("sha256:not-the-prepared-branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Bitcoin: &approvalBitcoin{}, Config: Config{
		Request: burnchain.ReorgRequest{
			Depth: 1, ReplacementBlocks: 2, Wallet: "miner", Address: "bcrt1qattacknet",
		},
		PreparationFile: preparation, ApprovalFile: approval,
		Listen:       "127.0.0.1:0",
		PollInterval: time.Millisecond,
	}}
	if err := worker.initialize(); err != nil {
		t.Fatal(err)
	}
	lifecycleErr := worker.runLifecycle(context.Background(), nil)
	if lifecycleErr == nil {
		t.Fatal("mismatched approval unexpectedly succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.retainTerminalStatus(ctx, make(chan error), lifecycleErr) }()
	t.Cleanup(cancel)

	deadline := time.Now().Add(time.Second)
	for {
		response := httptest.NewRecorder()
		worker.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if strings.Contains(response.Body.String(), `"phase":"Failed"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker failure did not become observable: %s", response.Body.String())
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("worker exited before deletion: %v", err)
	default:
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("worker deletion returned %v", err)
	}
}

func TestWorkerRefusesMismatchedApprovalWithoutMutation(t *testing.T) {
	t.Parallel()
	preparation := filepath.Join(t.TempDir(), "preparation")
	approval := filepath.Join(t.TempDir(), "approval")
	if err := os.WriteFile(preparation, []byte("sha256:paused-policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(approval, []byte("sha256:not-the-prepared-branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bitcoin := &approvalBitcoin{}
	worker := &Worker{Bitcoin: bitcoin, Config: Config{
		Request: burnchain.ReorgRequest{
			Depth: 1, ReplacementBlocks: 2, Wallet: "miner", Address: "bcrt1qattacknet",
		},
		PreparationFile: preparation, ApprovalFile: approval,
		Listen:       "127.0.0.1:0",
		PollInterval: time.Millisecond,
	}}
	if err := worker.initialize(); err != nil {
		t.Fatal(err)
	}
	err := worker.runLifecycle(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "does not match prepared digest") {
		t.Fatalf("Run() error = %v", err)
	}
	if bitcoin.invalidations != 0 {
		t.Fatalf("mismatched approval performed %d invalidations", bitcoin.invalidations)
	}
	worker.mu.RLock()
	defer worker.mu.RUnlock()
	if worker.status.Phase != "Failed" || worker.status.Prepared == nil || worker.status.Prepared.Digest == "" {
		t.Fatalf("unexpected terminal status: %#v", worker.status)
	}
}

func TestWorkerDoesNotObserveBitcoinBeforePreparationApproval(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	preparation, approval := filepath.Join(directory, "preparation"), filepath.Join(directory, "approval")
	for _, path := range []string{preparation, approval} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bitcoin := &approvalBitcoin{}
	worker := &Worker{Bitcoin: bitcoin, Config: Config{
		Request:         burnchain.ReorgRequest{Depth: 1, ReplacementBlocks: 2, Wallet: "miner", Address: "bcrt1qattacknet"},
		PreparationFile: preparation, ApprovalFile: approval, PollInterval: time.Millisecond,
	}}
	if err := worker.initialize(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.runLifecycle(ctx, nil) }()
	t.Cleanup(cancel)
	time.Sleep(20 * time.Millisecond)
	if bitcoin.chainInfoReads.Load() != 0 {
		t.Fatalf("worker observed Bitcoin %d times before preparation approval", bitcoin.chainInfoReads.Load())
	}
	worker.mu.RLock()
	phase := worker.status.Phase
	worker.mu.RUnlock()
	if phase != "WaitingForPreparation" {
		t.Fatalf("phase = %q, want WaitingForPreparation", phase)
	}
	if err := os.WriteFile(preparation, []byte("sha256:paused-policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for bitcoin.chainInfoReads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if bitcoin.chainInfoReads.Load() == 0 {
		t.Fatal("worker did not prepare after preparation approval")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("worker cancellation returned %v", err)
	}
}

type approvalBitcoin struct {
	invalidations  int
	chainInfoReads atomic.Int32
}

func (bitcoin *approvalBitcoin) ChainInfo(context.Context) (burnchain.ChainInfo, error) {
	bitcoin.chainInfoReads.Add(1)
	return burnchain.ChainInfo{Chain: "regtest", Blocks: 2, Headers: 2, BestBlockHash: "block-2", Chainwork: "03"}, nil
}

func (*approvalBitcoin) BlockHash(_ context.Context, height int64) (string, error) {
	if height < 0 || height > 2 {
		return "", errors.New("height unavailable")
	}
	return "block-" + strconv.FormatInt(height, 10), nil
}

func (*approvalBitcoin) BlockHeader(_ context.Context, hash string) (burnchain.BlockHeader, error) {
	switch hash {
	case "block-1":
		return burnchain.BlockHeader{Hash: hash, Height: 1, PreviousHash: "block-0", Chainwork: "02"}, nil
	case "block-2":
		return burnchain.BlockHeader{Hash: hash, Height: 2, PreviousHash: "block-1", Chainwork: "03", Confirmations: 1}, nil
	default:
		return burnchain.BlockHeader{}, errors.New("unknown block")
	}
}

func (*approvalBitcoin) ChainTips(context.Context) ([]burnchain.ChainTip, error) {
	return []burnchain.ChainTip{{Height: 2, Hash: "block-2", Status: "active"}}, nil
}

func (bitcoin *approvalBitcoin) InvalidateBlock(context.Context, string) error {
	bitcoin.invalidations++
	return nil
}

func (*approvalBitcoin) ReconsiderBlock(context.Context, string) error { return nil }

func (*approvalBitcoin) GenerateBlocks(context.Context, string, string, int32) ([]string, error) {
	return nil, errors.New("unexpected generation")
}
