package burnchain

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Wallet binds a watch-only Bitcoin wallet to its mining destination.
type Wallet struct {
	// Name is the watch-only Bitcoin Core wallet.
	Name string
	// Address receives this wallet's mined blocks.
	Address string
}

// Config contains process-lifetime clock settings, separate from runtime policy.
type Config struct {
	// Wallets are the mining destinations controlled by the clock.
	Wallets []Wallet
	// BootstrapHeight is reached idempotently before policy-controlled mining.
	BootstrapHeight uint64
	// ReserveOutputs mines this many initial outputs to each configured address.
	ReserveOutputs uint64
	// RetryInitial is the first Bitcoin RPC backoff duration.
	RetryInitial time.Duration
	// RetryMaximum bounds Bitcoin RPC backoff.
	RetryMaximum time.Duration
	// PausedPollInterval bounds policy-projection observation latency.
	PausedPollInterval time.Duration
}

// RandomSource provides deterministic bounded jitter.
type RandomSource interface {
	Uint64N(uint64) uint64
}

// Event interrupts the current cadence wait.
type Event uint8

const (
	// EventReload asks the clock to read projected policy immediately.
	EventReload Event = iota + 1
	// EventMineOne asks a paused clock to mine exactly one block.
	EventMineOne
)

// Clock owns resilient, policy-controlled burn-block production.
type Clock struct {
	// Config contains process-lifetime settings.
	Config Config
	// Bitcoin is the only external system the clock consults.
	Bitcoin Bitcoin
	// Policies supplies projected desired cadence.
	Policies PolicySource
	// Statuses receives local status acknowledgements.
	Statuses StatusSink
	// Logger receives structured operational messages.
	Logger *slog.Logger
	// Events interrupts cadence for reloads or explicit one-block requests.
	Events <-chan Event
	// Random deterministically selects jitter; nil means no jitter offset.
	Random RandomSource

	policy            Policy
	policyApplied     bool
	burstRemaining    uint64
	addressCursor     uint64
	lastBitcoinUptime *uint64
	forceBlock        bool
}

// Run bootstraps regtest and produces blocks until the context is cancelled.
func (clock *Clock) Run(ctx context.Context) error {
	if err := clock.validate(); err != nil {
		return err
	}
	clock.writeStatus("starting", nil, "bitcoin-rpc")
	if err := clock.retry(ctx, "wait for Bitcoin RPC", func() error {
		_, err := clock.Bitcoin.Height(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, wallet := range clock.Config.Wallets {
		current := wallet
		if err := clock.retry(ctx, "ensure wallet "+current.Name, func() error {
			return clock.Bitcoin.EnsureWatchOnlyWallet(ctx, current.Name)
		}); err != nil {
			return err
		}
	}
	if err := clock.retry(ctx, "reconcile wallets", func() error {
		return clock.reconcileAfterRestart(ctx, true)
	}); err != nil {
		return err
	}
	if err := clock.bootstrap(ctx); err != nil {
		return err
	}

	for ctx.Err() == nil {
		height, err := clock.height(ctx)
		if err != nil {
			return err
		}
		if err := clock.applyPolicy(height); err != nil {
			clock.writeStatus("degraded", &height, "invalid-policy")
			clock.logError("Policy projection is invalid; retaining the last admitted generation", err)
			if !clock.wait(ctx, clock.Config.PausedPollInterval) {
				break
			}
			continue
		}
		if clock.policy.Mode == ModePause && !clock.forceBlock && clock.burstRemaining == 0 {
			clock.writeStatus("paused", &height, fmt.Sprintf("policy-generation-%d", clock.policy.Generation))
			if !clock.wait(ctx, clock.Config.PausedPollInterval) {
				break
			}
			continue
		}
		if err := clock.reconcileAfterRestart(ctx, false); err != nil {
			clock.writeStatus("degraded", &height, "wallet-transaction-reconciliation")
			clock.logError("Could not reconcile wallets after Bitcoin restart", err)
			if !clock.wait(ctx, clock.Config.RetryInitial) {
				break
			}
			continue
		}
		wallet := clock.nextWallet()
		if err := clock.retry(ctx, "mine Bitcoin block", func() error {
			return clock.Bitcoin.MineBlock(ctx, wallet.Name, wallet.Address)
		}); err != nil {
			return err
		}
		height, err = clock.height(ctx)
		if err != nil {
			return err
		}
		clock.writeStatus("running", &height, "mined-to-"+wallet.Address)
		clock.Logger.Info("Mined Bitcoin block", "height", height, "address", wallet.Address)
		clock.forceBlock = false
		if clock.burstRemaining > 0 {
			clock.burstRemaining--
			if clock.burstRemaining == 0 {
				continue
			}
		}
		delay := time.Duration(clock.policy.IntervalSeconds) * time.Second
		if clock.policy.JitterSeconds > 0 && clock.Random != nil {
			delay += time.Duration(clock.Random.Uint64N(clock.policy.JitterSeconds+1)) * time.Second
		}
		if !clock.wait(ctx, delay) {
			break
		}
	}
	clock.writeStatus("stopped", nil, "terminated")
	return nil
}

func (clock *Clock) validate() error {
	if clock.Bitcoin == nil || clock.Policies == nil || clock.Statuses == nil {
		return fmt.Errorf("Bitcoin client, policy source, and status sink are required")
	}
	if clock.Logger == nil {
		clock.Logger = slog.Default()
	}
	if len(clock.Config.Wallets) == 0 {
		return fmt.Errorf("at least one miner wallet is required")
	}
	seenWallets := map[string]bool{}
	seenAddresses := map[string]bool{}
	for _, wallet := range clock.Config.Wallets {
		if wallet.Name == "" || wallet.Address == "" {
			return fmt.Errorf("miner wallet names and addresses must be non-empty")
		}
		if seenWallets[wallet.Name] || seenAddresses[wallet.Address] {
			return fmt.Errorf("miner wallets and addresses must be unique")
		}
		seenWallets[wallet.Name] = true
		seenAddresses[wallet.Address] = true
	}
	if clock.Config.ReserveOutputs == 0 {
		clock.Config.ReserveOutputs = 4
	}
	if clock.Config.RetryInitial <= 0 {
		clock.Config.RetryInitial = time.Second
	}
	if clock.Config.RetryMaximum < clock.Config.RetryInitial {
		clock.Config.RetryMaximum = clock.Config.RetryInitial
	}
	if clock.Config.PausedPollInterval <= 0 {
		clock.Config.PausedPollInterval = time.Second
	}
	return nil
}

func (clock *Clock) applyPolicy(height uint64) error {
	policy, err := clock.Policies.Load()
	if err != nil {
		return err
	}
	if policy.JitterSeconds > 0 && clock.Random == nil {
		return fmt.Errorf("policy requests jitter without a deterministic random source")
	}
	if clock.policyApplied {
		if policy.Generation < clock.policy.Generation {
			return fmt.Errorf("policy generation regressed from %d to %d", clock.policy.Generation, policy.Generation)
		}
		if policy.Generation == clock.policy.Generation {
			if policy != clock.policy {
				return fmt.Errorf("policy generation %d changed contents", policy.Generation)
			}
			return nil
		}
	}
	clock.policy = policy
	clock.policyApplied = true
	if policy.BurstTargetHeight > height {
		clock.burstRemaining = policy.BurstTargetHeight - height
	} else if policy.BurstTargetHeight > 0 {
		clock.burstRemaining = 0
	} else {
		clock.burstRemaining = policy.BurstBlocks
	}
	clock.Logger.Info("Applied burnchain policy", "generation", policy.Generation, "mode", policy.Mode,
		"intervalSeconds", policy.IntervalSeconds, "jitterSeconds", policy.JitterSeconds,
		"burstRemaining", clock.burstRemaining, "addressMode", policy.AddressMode)
	return nil
}

func (clock *Clock) bootstrap(ctx context.Context) error {
	height, err := clock.height(ctx)
	if err != nil {
		return err
	}
	if height == 0 {
		for _, wallet := range clock.Config.Wallets {
			for range clock.Config.ReserveOutputs {
				current := wallet
				if err := clock.retry(ctx, "mine reserve block", func() error {
					return clock.Bitcoin.MineBlock(ctx, current.Name, current.Address)
				}); err != nil {
					return err
				}
				height++
			}
		}
	}
	first := clock.Config.Wallets[0]
	for height < clock.Config.BootstrapHeight {
		if err := clock.retry(ctx, "mine bootstrap block", func() error {
			return clock.Bitcoin.MineBlock(ctx, first.Name, first.Address)
		}); err != nil {
			return err
		}
		height++
	}
	clock.writeStatus("running", &height, "bootstrapped")
	clock.Logger.Info("Bitcoin regtest clock ready", "height", height)
	return nil
}

func (clock *Clock) reconcileAfterRestart(ctx context.Context, force bool) error {
	uptime, err := clock.Bitcoin.Uptime(ctx)
	if err != nil {
		return err
	}
	if !force && clock.lastBitcoinUptime != nil && uptime >= *clock.lastBitcoinUptime {
		*clock.lastBitcoinUptime = uptime
		return nil
	}
	for _, wallet := range clock.Config.Wallets {
		// Bitcoin Core unloads named wallets when its process restarts, even
		// though their files remain on the persistent volume. Re-establish the
		// idempotent wallet session before querying transactions.
		if err := clock.Bitcoin.EnsureWatchOnlyWallet(ctx, wallet.Name); err != nil {
			return err
		}
		transactions, err := clock.Bitcoin.WalletTransactions(ctx, wallet.Name)
		if err != nil {
			return err
		}
		for _, transaction := range transactions {
			if transaction.Confirmations != 0 || transaction.Abandoned || !transaction.Sent {
				continue
			}
			active, err := clock.Bitcoin.InMempool(ctx, transaction.TxID)
			if err != nil {
				return err
			}
			if !active {
				if err := clock.Bitcoin.AbandonTransaction(ctx, wallet.Name, transaction.TxID); err != nil {
					return err
				}
				clock.Logger.Info("Abandoned inactive transaction after mempool reset", "wallet", wallet.Name, "txid", transaction.TxID)
			}
		}
	}
	clock.lastBitcoinUptime = &uptime
	clock.Logger.Info("Reconciled miner wallets against Bitcoin mempool", "uptimeSeconds", uptime)
	return nil
}

func (clock *Clock) nextWallet() Wallet {
	index := clock.addressCursor % uint64(len(clock.Config.Wallets))
	if clock.policy.AddressMode == AddressFixed {
		index = clock.policy.FixedAddressIndex % uint64(len(clock.Config.Wallets))
	} else {
		clock.addressCursor++
	}
	return clock.Config.Wallets[index]
}

func (clock *Clock) height(ctx context.Context) (uint64, error) {
	var height uint64
	err := clock.retry(ctx, "read Bitcoin height", func() error {
		var callErr error
		height, callErr = clock.Bitcoin.Height(ctx)
		return callErr
	})
	return height, err
}

func (clock *Clock) retry(ctx context.Context, operation string, call func() error) error {
	delay := clock.Config.RetryInitial
	for {
		if err := call(); err == nil {
			return nil
		} else {
			clock.writeStatus("degraded", nil, "bitcoin-rpc-retry")
			clock.logError(operation+" failed; retrying", err, "delay", delay)
		}
		if !clock.wait(ctx, delay) {
			return ctx.Err()
		}
		if delay < clock.Config.RetryMaximum {
			delay += time.Second
			if delay > clock.Config.RetryMaximum {
				delay = clock.Config.RetryMaximum
			}
		}
	}
}

func (clock *Clock) wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case event := <-clock.Events:
		if event == EventMineOne {
			clock.forceBlock = true
		}
		return true
	case <-timer.C:
		return true
	}
}

func (clock *Clock) writeStatus(state string, height *uint64, detail string) {
	status := Status{State: state, BitcoinHeight: height, Detail: detail, UpdatedAt: time.Now()}
	if clock.policyApplied {
		status.PolicyGeneration = &clock.policy.Generation
		status.PolicyMode = clock.policy.Mode
		status.IntervalSeconds = &clock.policy.IntervalSeconds
		status.AddressMode = clock.policy.AddressMode
	}
	if err := clock.Statuses.Write(status); err != nil {
		clock.logError("Could not persist burnchain status", err)
	}
}

func (clock *Clock) logError(message string, err error, attributes ...any) {
	attributes = append([]any{"error", err}, attributes...)
	clock.Logger.Error(message, attributes...)
}
