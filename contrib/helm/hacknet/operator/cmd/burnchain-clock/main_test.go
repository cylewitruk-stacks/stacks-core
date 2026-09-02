package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

func TestConfigureIsBoundedAndDeterministicallySeeded(t *testing.T) {
	t.Setenv("MINER_WALLETS", "wallet-a,wallet-b")
	t.Setenv("MINER_BTC_ADDRS", "address-a,address-b")
	t.Setenv("BURNCHAIN_RANDOM_SEED", "42")
	first, err := configure()
	if err != nil {
		t.Fatal(err)
	}
	second, err := configure()
	if err != nil {
		t.Fatal(err)
	}
	if first.healthAddress != "0.0.0.0:18500" || len(first.clock.Wallets) != 2 {
		t.Fatalf("unexpected defaults: %#v", first)
	}
	if got, want := first.random.Uint64N(10_000), second.random.Uint64N(10_000); got != want {
		t.Fatalf("same seed produced %d and %d", got, want)
	}
	t.Setenv("BURNCHAIN_DEFAULT_INTERVAL_SECONDS", "3601")
	if _, err := configure(); err == nil {
		t.Fatal("unbounded interval was accepted")
	}
}

func TestHealthServerIsMinimalAndMethodRestricted(t *testing.T) {
	t.Parallel()
	recorder := &burnchain.StatusRecorder{}
	server := healthServer("127.0.0.1:0", recorder)
	get := httptest.NewRecorder()
	server.Handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/", nil))
	if get.Code != http.StatusOK || get.Body.String() != "ok\n" {
		t.Fatalf("GET response = %d %q", get.Code, get.Body.String())
	}
	post := httptest.NewRecorder()
	server.Handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST response = %d", post.Code)
	}
	unavailable := httptest.NewRecorder()
	server.Handler.ServeHTTP(unavailable, httptest.NewRequest(http.MethodGet, "/status", nil))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty status response = %d", unavailable.Code)
	}
	height, generation := uint64(240), uint64(3)
	starting := httptest.NewRecorder()
	server.Handler.ServeHTTP(starting, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if starting.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty readiness response = %d", starting.Code)
	}
	if err := recorder.Write(burnchain.Status{State: "paused", BitcoinHeight: &height, PolicyGeneration: &generation}); err != nil {
		t.Fatal(err)
	}
	status := httptest.NewRecorder()
	server.Handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/status", nil))
	if status.Code != http.StatusOK || status.Body.String() == "" {
		t.Fatalf("status response = %d %q", status.Code, status.Body.String())
	}
	ready := httptest.NewRecorder()
	server.Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready response = %d %q", ready.Code, ready.Body.String())
	}
	if !clockReady(burnchain.Status{State: "running", BitcoinHeight: &height, PolicyGeneration: &generation}, true) ||
		clockReady(burnchain.Status{State: "starting", BitcoinHeight: &height, PolicyGeneration: &generation}, true) ||
		clockReady(burnchain.Status{State: "running", BitcoinHeight: &height}, true) {
		t.Fatal("clock readiness accepted an incomplete bootstrap or rejected an admitted clock")
	}
	metrics := httptest.NewRecorder()
	server.Handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), "attacknet_burnchain_clock_bitcoin_height 240") {
		t.Fatalf("metrics response = %d %q", metrics.Code, metrics.Body.String())
	}
}

func TestSignalsMapToClockEvents(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 2)
	events := make(chan burnchain.Event, 2)
	finished := make(chan struct{})
	go func() {
		translateSignals(ctx, signals, events)
		close(finished)
	}()
	signals <- syscall.SIGUSR1
	signals <- syscall.SIGUSR2
	for _, want := range []burnchain.Event{burnchain.EventMineOne, burnchain.EventReload} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %v, want %v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("signal translation timed out")
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("signal translator did not stop")
	}
}
