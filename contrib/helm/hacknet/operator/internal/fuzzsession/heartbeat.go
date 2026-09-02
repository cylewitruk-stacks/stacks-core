package fuzzsession

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
)

const (
	defaultLeaseRenewInterval = 30 * time.Second
	defaultLeaseRenewDeadline = 45 * time.Second
	defaultLeaseRetryInterval = 5 * time.Second
)

// leaseHeartbeat keeps the single-writer cluster Lease current while a session
// performs bounded work. A renewal failure cancels the work context immediately.
type leaseHeartbeat struct {
	mu        sync.Mutex
	lease     fuzzcorpus.ResourceIdentity
	err       error
	reported  bool
	cancel    context.CancelFunc
	done      chan struct{}
	stopOnce  sync.Once
	workAbort context.CancelCauseFunc
}

// startLeaseHeartbeat couples lease ownership to the active work context.
func (engine *Engine) startLeaseHeartbeat(
	parent context.Context,
	lease fuzzcorpus.ResourceIdentity,
	holder string,
) (context.Context, *leaseHeartbeat) {
	interval := engine.LeaseRenewInterval
	if interval <= 0 {
		interval = defaultLeaseRenewInterval
	}
	deadline := engine.LeaseRenewDeadline
	if deadline <= 0 {
		deadline = defaultLeaseRenewDeadline
	}
	retryInterval := engine.LeaseRetryInterval
	if retryInterval <= 0 {
		retryInterval = defaultLeaseRetryInterval
	}
	workContext, abortWork := context.WithCancelCause(parent)
	heartbeatContext, cancelHeartbeat := context.WithCancel(parent)
	heartbeat := &leaseHeartbeat{
		lease: lease, cancel: cancelHeartbeat, done: make(chan struct{}), workAbort: abortWork,
	}
	go heartbeat.run(heartbeatContext, engine.Runtime, holder, interval, deadline, retryInterval)
	return workContext, heartbeat
}

// run renews until stopped or until ownership can no longer be proven.
func (heartbeat *leaseHeartbeat) run(
	ctx context.Context,
	runtime Runtime,
	holder string,
	interval time.Duration,
	deadline time.Duration,
	retryInterval time.Duration,
) {
	defer close(heartbeat.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := heartbeat.current()
			renewed, err := renewLeaseUntil(ctx, runtime, current, holder, deadline, retryInterval)
			if err != nil && ctx.Err() != nil {
				return
			}
			if err != nil {
				heartbeat.fail(err)
				return
			}
			heartbeat.mu.Lock()
			heartbeat.lease = renewed
			heartbeat.mu.Unlock()
		}
	}
}

// renewLeaseUntil tolerates transport failures only while the last renewal is
// still valid; definitive identity loss aborts immediately.
func renewLeaseUntil(
	ctx context.Context,
	runtime Runtime,
	current fuzzcorpus.ResourceIdentity,
	holder string,
	deadline time.Duration,
	retryInterval time.Duration,
) (fuzzcorpus.ResourceIdentity, error) {
	if deadline <= 0 || retryInterval <= 0 || retryInterval >= deadline {
		return fuzzcorpus.ResourceIdentity{}, errors.New("valid lease renewal retry bounds are required")
	}
	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	var lastErr error
	for {
		renewed, err := runtime.RenewSession(ctx, current, holder)
		if err == nil && !sameLeaseIdentity(current, renewed) {
			err = fmt.Errorf("%w: renewed identity changed", errLeaseOwnershipLost)
		}
		if err == nil {
			return renewed, nil
		}
		if errors.Is(err, errLeaseOwnershipLost) {
			return fuzzcorpus.ResourceIdentity{}, err
		}
		lastErr = err
		retry := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			if !retry.Stop() {
				<-retry.C
			}
			return fuzzcorpus.ResourceIdentity{}, ctx.Err()
		case <-timeout.C:
			if !retry.Stop() {
				<-retry.C
			}
			return fuzzcorpus.ResourceIdentity{}, fmt.Errorf("lease renewal deadline exceeded: %w", lastErr)
		case <-retry.C:
		}
	}
}

// sameLeaseIdentity compares the immutable identity fields across renewals.
func sameLeaseIdentity(left, right fuzzcorpus.ResourceIdentity) bool {
	return left.APIVersion == right.APIVersion && left.Kind == right.Kind &&
		left.Namespace == right.Namespace && left.Name == right.Name && left.UID == right.UID
}

// current returns the last successfully observed Lease identity.
func (heartbeat *leaseHeartbeat) current() fuzzcorpus.ResourceIdentity {
	heartbeat.mu.Lock()
	defer heartbeat.mu.Unlock()
	return heartbeat.lease
}

// fail records the first renewal failure and aborts active session work.
func (heartbeat *leaseHeartbeat) fail(err error) {
	heartbeat.mu.Lock()
	if heartbeat.err == nil {
		heartbeat.err = err
	}
	heartbeat.mu.Unlock()
	heartbeat.workAbort(err)
}

// Stop terminates renewal and returns the last successfully renewed identity.
// It is idempotent so cleanup and deferred failure paths can both call it.
func (heartbeat *leaseHeartbeat) Stop() (fuzzcorpus.ResourceIdentity, error) {
	if heartbeat == nil {
		return fuzzcorpus.ResourceIdentity{}, nil
	}
	heartbeat.stopOnce.Do(heartbeat.cancel)
	<-heartbeat.done
	heartbeat.mu.Lock()
	defer heartbeat.mu.Unlock()
	return heartbeat.lease, heartbeat.err
}

// TakeError returns a heartbeat failure exactly once so cleanup and deferred
// paths cannot record the same ownership loss twice.
func (heartbeat *leaseHeartbeat) TakeError() error {
	if heartbeat == nil {
		return nil
	}
	heartbeat.mu.Lock()
	defer heartbeat.mu.Unlock()
	if heartbeat.reported || heartbeat.err == nil {
		return nil
	}
	heartbeat.reported = true
	return heartbeat.err
}
