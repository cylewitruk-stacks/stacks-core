package burnchain

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticPolicies struct{ policy Policy }

func (source staticPolicies) Load() (Policy, error) { return source.policy, nil }

type mutablePolicies struct{ policy Policy }

func (source *mutablePolicies) Load() (Policy, error) { return source.policy, nil }

type recordingStatuses struct {
	mu       sync.Mutex
	statuses []Status
	onWrite  func(Status)
}

func (sink *recordingStatuses) Write(status Status) error {
	sink.mu.Lock()
	sink.statuses = append(sink.statuses, status)
	sink.mu.Unlock()
	if sink.onWrite != nil {
		sink.onWrite(status)
	}
	return nil
}

type fakeBitcoin struct {
	mu             sync.Mutex
	height         uint64
	uptimes        []uint64
	mined          []Wallet
	transactions   map[string][]WalletTransaction
	inMempool      map[string]bool
	abandoned      []string
	heightFailures int
	txFailures     int
	heightCalls    int
	txCalls        int
	walletLoads    []string
	walletsLoaded  map[string]bool
	requireLoaded  bool
	lastUptime     *uint64
}

type observingBitcoin struct {
	*fakeBitcoin
	info  ChainInfo
	tips  []ChainTip
	peers []PeerInfo
}

func (bitcoin *observingBitcoin) ChainInfo(context.Context) (ChainInfo, error) {
	return bitcoin.info, nil
}

func (bitcoin *observingBitcoin) ChainTips(context.Context) ([]ChainTip, error) {
	return append([]ChainTip(nil), bitcoin.tips...), nil
}

func (bitcoin *observingBitcoin) PeerInfo(context.Context) ([]PeerInfo, error) {
	return append([]PeerInfo(nil), bitcoin.peers...), nil
}

func (bitcoin *fakeBitcoin) Height(context.Context) (uint64, error) {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	bitcoin.heightCalls++
	if bitcoin.heightFailures > 0 {
		bitcoin.heightFailures--
		return 0, fmt.Errorf("temporary height failure")
	}
	return bitcoin.height, nil
}

func (bitcoin *fakeBitcoin) Uptime(context.Context) (uint64, error) {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if len(bitcoin.uptimes) == 0 {
		return 100, nil
	}
	uptime := bitcoin.uptimes[0]
	bitcoin.uptimes = bitcoin.uptimes[1:]
	if bitcoin.lastUptime != nil && uptime < *bitcoin.lastUptime {
		bitcoin.walletsLoaded = map[string]bool{}
	}
	bitcoin.lastUptime = &uptime
	return uptime, nil
}

func (bitcoin *fakeBitcoin) EnsureWatchOnlyWallet(_ context.Context, wallet string) error {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	bitcoin.walletLoads = append(bitcoin.walletLoads, wallet)
	if bitcoin.walletsLoaded == nil {
		bitcoin.walletsLoaded = map[string]bool{}
	}
	bitcoin.walletsLoaded[wallet] = true
	return nil
}

func (bitcoin *fakeBitcoin) WalletTransactions(_ context.Context, wallet string) ([]WalletTransaction, error) {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	bitcoin.txCalls++
	if bitcoin.requireLoaded && !bitcoin.walletsLoaded[wallet] {
		return nil, fmt.Errorf("wallet %s is not loaded", wallet)
	}
	if bitcoin.txFailures > 0 {
		bitcoin.txFailures--
		return nil, fmt.Errorf("temporary wallet failure")
	}
	return append([]WalletTransaction(nil), bitcoin.transactions[wallet]...), nil
}

func (bitcoin *fakeBitcoin) InMempool(_ context.Context, txID string) (bool, error) {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	return bitcoin.inMempool[txID], nil
}

func (bitcoin *fakeBitcoin) AbandonTransaction(_ context.Context, wallet, txID string) error {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	bitcoin.abandoned = append(bitcoin.abandoned, wallet+":"+txID)
	for index, transaction := range bitcoin.transactions[wallet] {
		if transaction.TxID == txID {
			bitcoin.transactions[wallet][index].Abandoned = true
		}
	}
	return nil
}

func (bitcoin *fakeBitcoin) MineBlock(_ context.Context, wallet, address string) error {
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	bitcoin.height++
	bitcoin.mined = append(bitcoin.mined, Wallet{Name: wallet, Address: address})
	return nil
}

func TestClockObservationIsCompleteBoundedAndSorted(t *testing.T) {
	bitcoin := &observingBitcoin{
		fakeBitcoin: &fakeBitcoin{},
		info:        ChainInfo{Chain: "regtest", Blocks: 10, Headers: 10, BestBlockHash: strings.Repeat("a", 64), Chainwork: strings.Repeat("b", 64)},
		tips: []ChainTip{
			{Height: 9, Hash: strings.Repeat("d", 64), BranchLen: 1, Status: "valid-fork"},
			{Height: 10, Hash: strings.Repeat("c", 64), Status: "active"},
		},
		peers: []PeerInfo{
			{ID: 2, Address: "node-b:18444", ConnectionType: "manual"},
			{ID: 1, Address: "node-a:18444", ConnectionType: "manual"},
		},
	}
	clock := Clock{Bitcoin: bitcoin}
	status := Status{}
	clock.observe(context.Background(), &status)
	if status.ObservationError != "" || status.ChainInfo == nil || status.ChainTips[0].Hash != strings.Repeat("c", 64) || status.Peers[0].ID != 1 {
		t.Fatalf("complete observation was not normalized: %#v", status)
	}

	bitcoin.peers[0].Address = strings.Repeat("x", 257)
	status = Status{}
	clock.observe(context.Background(), &status)
	if status.ObservationError != "peer-info-invalid" || status.ChainInfo != nil || len(status.ChainTips) != 0 || len(status.Peers) != 0 {
		t.Fatalf("invalid partial observation escaped: %#v", status)
	}
}

func TestCadenceWaitRefreshesBranchObservation(t *testing.T) {
	bitcoin := &observingBitcoin{fakeBitcoin: &fakeBitcoin{}, info: ChainInfo{
		Chain: "regtest", Blocks: 10, Headers: 10, BestBlockHash: strings.Repeat("a", 64), Chainwork: strings.Repeat("b", 64),
	}}
	statuses := &recordingStatuses{}
	clock := Clock{Bitcoin: bitcoin, Statuses: statuses, Config: Config{PausedPollInterval: time.Millisecond}}
	if !clock.waitCadence(context.Background(), 5*time.Millisecond) {
		t.Fatal("cadence wait ended early")
	}
	statuses.mu.Lock()
	defer statuses.mu.Unlock()
	if len(statuses.statuses) == 0 || statuses.statuses[len(statuses.statuses)-1].ChainInfo == nil {
		t.Fatalf("cadence wait did not refresh the branch observation: %#v", statuses.statuses)
	}
}

func TestCadenceWaitRemainsPolicyInterruptible(t *testing.T) {
	events := make(chan Event, 1)
	clock := Clock{Events: events, Config: Config{PausedPollInterval: time.Hour}}
	events <- EventMineOne
	started := time.Now()
	if !clock.waitCadence(context.Background(), time.Hour) {
		t.Fatal("cadence wait unexpectedly stopped")
	}
	if time.Since(started) > time.Second {
		t.Fatal("cadence wait did not react promptly to the event")
	}
	if !clock.forceBlock {
		t.Fatal("mine-one event did not survive cadence interruption")
	}
}

func TestClockBootstrapAndExactBurstAreIdempotent(t *testing.T) {
	t.Parallel()
	bitcoin := &fakeBitcoin{height: 0, transactions: map[string][]WalletTransaction{}, inMempool: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	statuses := &recordingStatuses{}
	statuses.onWrite = func(status Status) {
		if status.State == "paused" && status.BitcoinHeight != nil && *status.BitcoinHeight == 12 {
			cancel()
		}
	}
	clock := testClock(bitcoin, statuses, Policy{
		Generation: 1, Mode: ModePause, IntervalSeconds: 0,
		BurstBlocks: 20, BurstTargetHeight: 12, AddressMode: AddressRoundRobin,
	})
	clock.Config.BootstrapHeight = 10
	clock.Config.ReserveOutputs = 2
	if err := clock.Run(ctx); err != nil {
		t.Fatal(err)
	}
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if bitcoin.height != 12 || len(bitcoin.mined) != 12 {
		t.Fatalf("expected exact target height 12, got height=%d mined=%d", bitcoin.height, len(bitcoin.mined))
	}
	wantPrefix := []Wallet{{"wallet-a", "address-a"}, {"wallet-a", "address-a"}, {"wallet-b", "address-b"}, {"wallet-b", "address-b"}}
	for index, want := range wantPrefix {
		if bitcoin.mined[index] != want {
			t.Fatalf("reserve destination %d = %#v, want %#v", index, bitcoin.mined[index], want)
		}
	}
}

func TestClockAllowsSecondaryNodeWithoutReserveMining(t *testing.T) {
	t.Parallel()
	bitcoin := &fakeBitcoin{height: 0, transactions: map[string][]WalletTransaction{}, inMempool: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	statuses := &recordingStatuses{onWrite: func(status Status) {
		if status.State == "paused" {
			cancel()
		}
	}}
	clock := testClock(bitcoin, statuses, Policy{Generation: 1, Mode: ModePause, AddressMode: AddressRoundRobin})
	clock.Config.BootstrapHeight = 0
	clock.Config.ReserveOutputs = 0
	if err := clock.Run(ctx); err != nil {
		t.Fatal(err)
	}
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if bitcoin.height != 0 || len(bitcoin.mined) != 0 {
		t.Fatalf("secondary policy mutated the shared chain: height=%d mined=%d", bitcoin.height, len(bitcoin.mined))
	}
}

func TestClockReconcilesOnlyInactiveSendsAfterBitcoinRestart(t *testing.T) {
	t.Parallel()
	bitcoin := &fakeBitcoin{
		height: 10, uptimes: []uint64{100, 10}, inMempool: map[string]bool{"active": true},
		requireLoaded: true,
		transactions: map[string][]WalletTransaction{"wallet-a": {
			{TxID: "stale", Sent: true}, {TxID: "active", Sent: true},
			{TxID: "received"}, {TxID: "confirmed", Sent: true, Confirmations: 1},
			{TxID: "abandoned", Sent: true, Abandoned: true},
		}},
	}
	clock := testClock(bitcoin, &recordingStatuses{}, Policy{Generation: 1, Mode: ModePause, AddressMode: AddressRoundRobin})
	clock.Config.Wallets = clock.Config.Wallets[:1]
	if err := clock.validate(); err != nil {
		t.Fatal(err)
	}
	if err := clock.reconcileAfterRestart(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := clock.reconcileAfterRestart(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if len(bitcoin.abandoned) != 1 || bitcoin.abandoned[0] != "wallet-a:stale" {
		t.Fatalf("unexpected abandoned transactions: %#v", bitcoin.abandoned)
	}
	if got := len(bitcoin.walletLoads); got != 2 {
		t.Fatalf("wallet loads = %d, want one before each reconciliation", got)
	}
}

func TestPausedClockRespondsToExplicitBlockRequest(t *testing.T) {
	t.Parallel()
	bitcoin := &fakeBitcoin{height: 10, transactions: map[string][]WalletTransaction{}, inMempool: map[string]bool{}}
	events := make(chan Event, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	statuses := &recordingStatuses{}
	statuses.onWrite = func(status Status) {
		if status.State == "paused" && status.BitcoinHeight != nil {
			if *status.BitcoinHeight == 10 {
				select {
				case events <- EventMineOne:
				default:
				}
			} else if *status.BitcoinHeight == 11 {
				cancel()
			}
		}
	}
	clock := testClock(bitcoin, statuses, Policy{Generation: 1, Mode: ModePause, AddressMode: AddressFixed, FixedAddressIndex: 1})
	clock.Events = events
	if err := clock.Run(ctx); err != nil {
		t.Fatal(err)
	}
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if len(bitcoin.mined) != 1 || bitcoin.mined[0].Address != "address-b" {
		t.Fatalf("explicit block request mined %#v", bitcoin.mined)
	}
}

func TestPolicyGenerationIsMonotonicAndImmutable(t *testing.T) {
	t.Parallel()
	source := &mutablePolicies{policy: Policy{Generation: 4, Mode: ModePause, AddressMode: AddressRoundRobin}}
	clock := testClock(&fakeBitcoin{}, &recordingStatuses{}, source.policy)
	clock.Policies = source
	if err := clock.applyPolicy(10); err != nil {
		t.Fatal(err)
	}
	source.policy.IntervalSeconds = 2
	if err := clock.applyPolicy(10); err == nil {
		t.Fatal("changed contents under generation 4 were accepted")
	}
	source.policy.Generation = 3
	if err := clock.applyPolicy(10); err == nil {
		t.Fatal("regressed generation was accepted")
	}
	source.policy.Generation = 5
	if err := clock.applyPolicy(10); err != nil {
		t.Fatalf("new generation was rejected: %v", err)
	}
}

func TestClockRetriesTransientBitcoinStartupFailures(t *testing.T) {
	t.Parallel()
	bitcoin := &fakeBitcoin{
		height: 10, heightFailures: 2, txFailures: 2,
		transactions: map[string][]WalletTransaction{}, inMempool: map[string]bool{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	statuses := &recordingStatuses{onWrite: func(status Status) {
		if status.State == "paused" {
			cancel()
		}
	}}
	clock := testClock(bitcoin, statuses, Policy{Generation: 1, Mode: ModePause, AddressMode: AddressRoundRobin})
	clock.Config.Wallets = clock.Config.Wallets[:1]
	if err := clock.Run(ctx); err != nil {
		t.Fatal(err)
	}
	bitcoin.mu.Lock()
	defer bitcoin.mu.Unlock()
	if bitcoin.heightCalls < 3 || bitcoin.txCalls < 3 {
		t.Fatalf("startup operations were not retried: height=%d wallet=%d", bitcoin.heightCalls, bitcoin.txCalls)
	}
}

func testClock(bitcoin Bitcoin, statuses StatusSink, policy Policy) *Clock {
	return &Clock{
		Config: Config{
			Wallets:         []Wallet{{"wallet-a", "address-a"}, {"wallet-b", "address-b"}},
			BootstrapHeight: 10, ReserveOutputs: 2, RetryInitial: time.Millisecond,
			RetryMaximum: time.Millisecond, PausedPollInterval: time.Millisecond,
		},
		Bitcoin: bitcoin, Policies: staticPolicies{policy: policy}, Statuses: statuses,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
