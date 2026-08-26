package burnchainpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchain"
)

const maximumStatusBytes = 64 << 10

// StatusReader reads one credential-free clock status endpoint.
type StatusReader interface {
	Read(context.Context, string) (burnchain.Status, error)
}

// HTTPStatusReader reads a fixed path and port from an API-observed Pod IP.
type HTTPStatusReader struct {
	Client *http.Client
}

// Read fetches and validates one bounded clock status document.
func (reader HTTPStatusReader) Read(ctx context.Context, podIP string) (burnchain.Status, error) {
	if reader.Client == nil {
		return burnchain.Status{}, fmt.Errorf("HTTP status client is required")
	}
	if net.ParseIP(podIP) == nil {
		return burnchain.Status{}, fmt.Errorf("clock Pod IP %q is invalid", podIP)
	}
	endpoint := url.URL{Scheme: "http", Host: net.JoinHostPort(podIP, strconv.Itoa(int(clockHealthPort))), Path: "/status"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return burnchain.Status{}, fmt.Errorf("build clock status request: %w", err)
	}
	response, err := reader.Client.Do(request)
	if err != nil {
		return burnchain.Status{}, fmt.Errorf("read clock status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return burnchain.Status{}, fmt.Errorf("clock status returned HTTP %s", response.Status)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maximumStatusBytes+1))
	if err != nil {
		return burnchain.Status{}, fmt.Errorf("read clock status body: %w", err)
	}
	if len(contents) > maximumStatusBytes {
		return burnchain.Status{}, fmt.Errorf("clock status exceeds %d bytes", maximumStatusBytes)
	}
	var status burnchain.Status
	if err := json.Unmarshal(contents, &status); err != nil {
		return burnchain.Status{}, fmt.Errorf("decode clock status: %w", err)
	}
	if status.State == "" {
		return burnchain.Status{}, fmt.Errorf("clock status state is empty")
	}
	switch status.State {
	case "starting", "running", "paused", "degraded", "stopped":
	default:
		return burnchain.Status{}, fmt.Errorf("clock status state %q is unsupported", status.State)
	}
	return status, nil
}
