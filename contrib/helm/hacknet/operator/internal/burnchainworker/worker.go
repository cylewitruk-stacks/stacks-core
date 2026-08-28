// Package burnchainworker runs the credential-isolated Bitcoin reorg process.
package burnchainworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

// Status is the complete bounded state served to the trusted controller.
type Status struct {
	SchemaVersion string                   `json:"schemaVersion"`
	Phase         string                   `json:"phase"`
	Preparation   string                   `json:"preparation,omitempty"`
	Prepared      *burnchain.PreparedReorg `json:"prepared,omitempty"`
	Result        *burnchain.ReorgResult   `json:"result,omitempty"`
	Failure       string                   `json:"failure,omitempty"`
	UpdatedAt     time.Time                `json:"updatedAt"`
}

// Config defines the worker's fixed request, approval, and HTTP boundaries.
type Config struct {
	Request         burnchain.ReorgRequest
	PreparationFile string
	ApprovalFile    string
	Listen          string
	PollInterval    time.Duration
}

// Worker executes one prepare/approve/recheck/mutate lifecycle.
type Worker struct {
	Bitcoin burnchain.ReorgBitcoin
	Config  Config
	mu      sync.RWMutex
	status  Status
}

type statusTransportError struct {
	err error
}

func (failure statusTransportError) Error() string { return failure.err.Error() }

func (failure statusTransportError) Unwrap() error { return failure.err }

// Run serves status, waits for exact approval, and executes the bounded reorg.
func (worker *Worker) Run(ctx context.Context) error {
	if err := worker.initialize(); err != nil {
		return err
	}
	server := &http.Server{Addr: worker.Config.Listen, Handler: worker.Handler(), ReadHeaderTimeout: 2 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	defer server.Shutdown(context.WithoutCancel(ctx))
	return worker.retainTerminalStatus(ctx, serverErrors, worker.runLifecycle(ctx, serverErrors))
}

func (worker *Worker) retainTerminalStatus(ctx context.Context, serverErrors <-chan error, err error) error {
	var transportFailure statusTransportError
	if err == nil || errors.As(err, &transportFailure) || errors.Is(err, context.Canceled) {
		return err
	}
	// A semantic failure is part of the campaign evidence. Keep the bounded
	// status endpoint alive until the controller captures it and deletes the
	// worker. Only a status-transport failure is terminal immediately.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case transportErr := <-serverErrors:
		return transportErr
	}
}

// initialize validates and normalizes the worker's immutable configuration.
func (worker *Worker) initialize() error {
	if worker.Bitcoin == nil {
		return errors.New("Bitcoin client is required")
	}
	if worker.Config.PreparationFile == "" || worker.Config.ApprovalFile == "" {
		return errors.New("preparation and approval files are required")
	}
	if worker.Config.PollInterval <= 0 {
		worker.Config.PollInterval = 250 * time.Millisecond
	}
	if worker.Config.Listen == "" {
		worker.Config.Listen = ":8090"
	}
	worker.set(Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "WaitingForPreparation"})
	return nil
}

// runLifecycle executes the approval protocol independently of status transport.
func (worker *Worker) runLifecycle(ctx context.Context, serverErrors <-chan error) error {
	preparation, err := worker.waitForValue(ctx, serverErrors, worker.Config.PreparationFile, "preparation", nil)
	if err != nil {
		worker.fail(err)
		return err
	}
	worker.set(Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Preparing", Preparation: preparation})
	prepared, err := burnchain.PrepareReorg(ctx, worker.Bitcoin, worker.Config.Request)
	if err != nil {
		worker.fail(err)
		return err
	}
	worker.set(Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Prepared", Preparation: preparation, Prepared: &prepared})
	if _, err := worker.waitForValue(ctx, serverErrors, worker.Config.ApprovalFile, "approval", func(value string) error {
		if value != prepared.Digest {
			return fmt.Errorf("approval digest %q does not match prepared digest %q", value, prepared.Digest)
		}
		return nil
	}); err != nil {
		worker.fail(err)
		return err
	}
	worker.set(Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Executing", Preparation: preparation, Prepared: &prepared})
	result, executeErr := burnchain.ExecuteReorg(ctx, worker.Bitcoin, prepared, waitContext)
	if executeErr != nil {
		status := Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Failed", Preparation: preparation, Result: &result, Failure: executeErr.Error()}
		worker.set(status)
		return executeErr
	}
	worker.set(Status{SchemaVersion: "attacknet-burnchain-reorg-worker/v1", Phase: "Succeeded", Preparation: preparation, Result: &result})
	<-ctx.Done()
	return ctx.Err()
}

func (worker *Worker) waitForValue(ctx context.Context, serverErrors <-chan error, path, label string, validate func(string) error) (string, error) {
	ticker := time.NewTicker(worker.Config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case err := <-serverErrors:
			return "", statusTransportError{err: err}
		case <-ticker.C:
			contents, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("read %s: %w", label, err)
			}
			value := strings.TrimSpace(string(contents))
			if value == "" {
				continue
			}
			if validate != nil {
				if err := validate(value); err != nil {
					return "", err
				}
			}
			return value, nil
		}
	}
}

// Handler exposes only the immutable bounded worker status.
func (worker *Worker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		worker.mu.RLock()
		defer worker.mu.RUnlock()
		_ = json.NewEncoder(response).Encode(worker.status)
	})
	return mux
}

func (worker *Worker) set(status Status) {
	status.UpdatedAt = time.Now().UTC()
	worker.mu.Lock()
	worker.status = status
	worker.mu.Unlock()
}

func (worker *Worker) fail(err error) {
	worker.mu.RLock()
	status := worker.status
	worker.mu.RUnlock()
	status.Phase, status.Failure = "Failed", err.Error()
	worker.set(status)
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Main loads the worker's fixed environment and blocks until termination.
func Main() int {
	var request burnchain.ReorgRequest
	if err := json.Unmarshal([]byte(os.Getenv("ATTACKNET_REORG_REQUEST_JSON")), &request); err != nil {
		fmt.Fprintf(os.Stderr, "decode ATTACKNET_REORG_REQUEST_JSON: %v\n", err)
		return 2
	}
	endpoint, err := url.Parse(os.Getenv("BITCOIN_RPC_URL"))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		fmt.Fprintf(os.Stderr, "invalid BITCOIN_RPC_URL\n")
		return 2
	}
	timeout := 15 * time.Second
	client := &burnchain.RPCClient{
		Endpoint: endpoint, Username: os.Getenv("BITCOIN_RPC_USERNAME"), Password: os.Getenv("BITCOIN_RPC_PASSWORD"),
		HTTPClient: &http.Client{Timeout: timeout},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	worker := &Worker{Bitcoin: client, Config: Config{
		Request:         request,
		PreparationFile: defaultString(os.Getenv("ATTACKNET_REORG_PREPARATION_FILE"), "/var/run/attacknet-reorg/preparation"),
		ApprovalFile:    defaultString(os.Getenv("ATTACKNET_REORG_APPROVAL_FILE"), "/var/run/attacknet-reorg/approval"),
		Listen:          defaultString(os.Getenv("ATTACKNET_REORG_LISTEN"), ":8090"),
	}}
	if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "burnchain reorg worker failed: %v\n", err)
		return 1
	}
	return 0
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
