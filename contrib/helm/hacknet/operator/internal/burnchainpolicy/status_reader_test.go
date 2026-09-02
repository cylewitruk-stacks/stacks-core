package burnchainpolicy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPStatusReaderUsesFixedEndpointAndRejectsUnknownState(t *testing.T) {
	requested := ""
	reader := HTTPStatusReader{Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = request.URL.String()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"state":"invented"}`))}, nil
	})}}
	if _, err := reader.Read(context.Background(), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected status state was accepted: %v", err)
	}
	if requested != "http://127.0.0.1:18500/status" {
		t.Fatalf("status reader contacted unexpected endpoint %q", requested)
	}
}

func TestHTTPStatusReaderRejectsUnboundedOrInvalidInput(t *testing.T) {
	reader := HTTPStatusReader{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maximumStatusBytes+1)))}, nil
	})}}
	if _, err := reader.Read(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("invalid Pod IP was accepted")
	}
	if _, err := reader.Read(context.Background(), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized status was accepted: %v", err)
	}
}
