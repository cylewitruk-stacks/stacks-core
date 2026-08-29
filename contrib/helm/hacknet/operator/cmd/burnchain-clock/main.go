// Command burnchain-clock runs the credential-free, Stacks-blind regtest clock.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

const (
	defaultPolicyPath = "/run/hacknet-policy/policy.env"
	defaultStatusPath = "/tmp/hacknet-burnchain-clock.env"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	runtime, err := configure()
	if err != nil {
		logger.Error("Invalid burnchain-clock configuration", "error", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	events := make(chan burnchain.Event, 1)
	policySignals := make(chan os.Signal, 1)
	signal.Notify(policySignals, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(policySignals)
	go translateSignals(ctx, policySignals, events)

	recorder := &burnchain.StatusRecorder{Delegate: runtime.statuses}
	server := healthServer(runtime.healthAddress, recorder)
	go func() {
		logger.Info("Burnchain health endpoint listening", "address", runtime.healthAddress)
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("Burnchain health endpoint stopped", "error", serveErr)
			cancel()
		}
	}()
	clock := &burnchain.Clock{
		Config: runtime.clock, Bitcoin: runtime.client, Policies: runtime.policies,
		Statuses: recorder, Logger: logger, Events: events, Random: runtime.random,
	}
	if err := clock.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("Burnchain clock stopped", "error", err)
		os.Exit(1)
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Could not stop health endpoint cleanly", "error", err)
	}
}

type runtimeConfig struct {
	clock         burnchain.Config
	client        *burnchain.RPCClient
	policies      burnchain.PolicySource
	statuses      burnchain.StatusSink
	healthAddress string
	random        burnchain.RandomSource
}

func configure() (runtimeConfig, error) {
	walletNames, err := csv("MINER_WALLETS")
	if err != nil {
		return runtimeConfig{}, err
	}
	addresses, err := csv("MINER_BTC_ADDRS")
	if err != nil {
		return runtimeConfig{}, err
	}
	if len(walletNames) != len(addresses) {
		return runtimeConfig{}, fmt.Errorf("MINER_WALLETS and MINER_BTC_ADDRS must have equal lengths")
	}
	wallets := make([]burnchain.Wallet, len(walletNames))
	for index := range walletNames {
		wallets[index] = burnchain.Wallet{Name: walletNames[index], Address: addresses[index]}
	}
	bootstrap, err := boundedUint("BURNCHAIN_BOOTSTRAP_HEIGHT", 202, 0, 10_000_000)
	if err != nil {
		return runtimeConfig{}, err
	}
	reserve, err := boundedUint("BURNCHAIN_MINER_RESERVE_OUTPUTS", 4, 0, 10_000)
	if err != nil {
		return runtimeConfig{}, err
	}
	interval, err := boundedUint("BURNCHAIN_DEFAULT_INTERVAL_SECONDS", 60, 0, 3600)
	if err != nil {
		return runtimeConfig{}, err
	}
	port, err := boundedUint("BITCOIN_RPC_PORT", 18443, 1, 65535)
	if err != nil {
		return runtimeConfig{}, err
	}
	healthPort, err := boundedUint("BURNCHAIN_HEALTH_PORT", 18500, 1, 65535)
	if err != nil {
		return runtimeConfig{}, err
	}
	seed, err := boundedUint("BURNCHAIN_RANDOM_SEED", 1, 0, ^uint64(0))
	if err != nil {
		return runtimeConfig{}, err
	}
	rpcTimeout, err := boundedUint("BURNCHAIN_RPC_TIMEOUT_SECONDS", 30, 1, 300)
	if err != nil {
		return runtimeConfig{}, err
	}
	retryInitial, err := boundedUint("BURNCHAIN_RETRY_INITIAL_SECONDS", 1, 1, 60)
	if err != nil {
		return runtimeConfig{}, err
	}
	retryMaximum, err := boundedUint("BURNCHAIN_RETRY_MAXIMUM_SECONDS", 10, retryInitial, 300)
	if err != nil {
		return runtimeConfig{}, err
	}
	host := envOr("BITCOIN_RPC_HOST", "bitcoin")
	if net.ParseIP(host) == nil {
		if err := validateDNSName(host); err != nil {
			return runtimeConfig{}, fmt.Errorf("BITCOIN_RPC_HOST: %w", err)
		}
	}
	endpoint, err := url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort(host, strconv.FormatUint(port, 10))))
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("Bitcoin RPC endpoint: %w", err)
	}
	defaults := burnchain.PolicyDefaults{IntervalSeconds: interval, MaxDelaySeconds: 3600}
	configuration := burnchain.Config{
		Wallets: wallets, BootstrapHeight: bootstrap, ReserveOutputs: reserve,
		RetryInitial: time.Duration(retryInitial) * time.Second,
		RetryMaximum: time.Duration(retryMaximum) * time.Second, PausedPollInterval: time.Second,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &burnchain.RPCClient{
		Endpoint: endpoint, Username: envOr("BITCOIN_RPC_USER", "devnet"),
		Password: envOr("BITCOIN_RPC_PASSWORD", "devnet"),
		HTTPClient: &http.Client{
			Transport: transport, Timeout: time.Duration(rpcTimeout) * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	policies := burnchain.FilePolicySource{Path: envOr("BURNCHAIN_POLICY_FILE", defaultPolicyPath), Defaults: defaults}
	statuses := burnchain.FileStatusSink{Path: envOr("BURNCHAIN_STATUS_FILE", defaultStatusPath)}
	return runtimeConfig{
		clock: configuration, client: client, policies: policies, statuses: statuses,
		healthAddress: net.JoinHostPort("0.0.0.0", strconv.FormatUint(healthPort, 10)),
		random:        rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}, nil
}

func translateSignals(ctx context.Context, signals <-chan os.Signal, events chan<- burnchain.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case signalValue := <-signals:
			event := burnchain.EventReload
			if signalValue == syscall.SIGUSR1 {
				event = burnchain.EventMineOne
			}
			select {
			case events <- event:
			default:
			}
		}
	}
}

type statusSource interface {
	Snapshot() (burnchain.Status, bool)
}

func healthServer(address string, statuses statusSource) *http.Server {
	mux := http.NewServeMux()
	registry := prometheus.NewRegistry()
	registry.MustRegister(burnchain.NewStatusCollector(statuses))
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = writer.Write([]byte("ok\n"))
		}
	})
	mux.HandleFunc("/status", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		status, observed := statuses.Snapshot()
		if !observed {
			http.Error(writer, "status unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(writer).Encode(status)
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		status, observed := statuses.Snapshot()
		if !clockReady(status, observed) {
			http.Error(writer, "clock not ready", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
}

func clockReady(status burnchain.Status, observed bool) bool {
	return observed && status.PolicyGeneration != nil && status.BitcoinHeight != nil &&
		status.ObservationError == "" && (status.State == "running" || status.State == "paused")
}

func csv(name string) ([]string, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" || strings.ContainsAny(item, "\r\n") {
			return nil, fmt.Errorf("%s contains an empty or invalid item", name)
		}
		if seen[item] {
			return nil, fmt.Errorf("%s contains duplicate item %q", name, item)
		}
		seen[item] = true
		result = append(result, item)
	}
	return result, nil
}

func boundedUint(name string, fallback, minimum, maximum uint64) (uint64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d", name, minimum, maximum)
	}
	return value, nil
}

func validateDNSName(value string) error {
	if len(value) == 0 || len(value) > 253 {
		return fmt.Errorf("DNS name length is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS label %q is invalid", label)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("DNS label %q is invalid", label)
			}
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
