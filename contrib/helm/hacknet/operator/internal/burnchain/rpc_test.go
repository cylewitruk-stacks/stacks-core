package burnchain

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRPCClientUsesAuthenticatedBoundedWalletRequests(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "user" || password != "pass" {
			t.Fatalf("unexpected Basic auth: %q %q %v", username, password, ok)
		}
		var payload rpcRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		body := ""
		switch payload.Method {
		case "getblockcount":
			body = `{"result":240,"error":null}`
		case "generatetoaddress":
			if request.URL.Path != "/wallet/miner-1" {
				t.Fatalf("wallet path = %q", request.URL.Path)
			}
			body = `{"result":["block"],"error":null}`
		case "getmempoolentry":
			body = `{"result":null,"error":{"code":-5,"message":"not found"}}`
		default:
			t.Fatalf("unexpected method %q", payload.Method)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})
	endpoint, err := url.Parse("http://bitcoin:18443")
	if err != nil {
		t.Fatal(err)
	}
	client := &RPCClient{Endpoint: endpoint, Username: "user", Password: "pass", HTTPClient: &http.Client{Transport: transport}}
	height, err := client.Height(context.Background())
	if err != nil || height != 240 {
		t.Fatalf("Height() = %d, %v", height, err)
	}
	if err := client.MineBlock(context.Background(), "miner-1", "address"); err != nil {
		t.Fatal(err)
	}
	active, err := client.InMempool(context.Background(), "txid")
	if err != nil || active {
		t.Fatalf("InMempool() = %v, %v", active, err)
	}
}

func TestEnsureWatchOnlyWalletDoesNotRequirePersistentSettings(t *testing.T) {
	t.Parallel()
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload rpcRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		requests++
		body := `{"result":{},"error":null}`
		switch payload.Method {
		case "createwallet":
			parameters, ok := payload.Params.(map[string]any)
			if !ok {
				t.Fatalf("createwallet parameters = %#v", payload.Params)
			}
			if load, ok := parameters["load_on_startup"].(bool); !ok || load {
				t.Fatalf("load_on_startup = %#v; -nosettings requires false", parameters["load_on_startup"])
			}
		case "getwalletinfo":
			if request.URL.Path != "/wallet/miner-1" {
				t.Fatalf("wallet path = %q", request.URL.Path)
			}
		default:
			t.Fatalf("unexpected method %q", payload.Method)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	endpoint, err := url.Parse("http://bitcoin:18443")
	if err != nil {
		t.Fatal(err)
	}
	client := &RPCClient{Endpoint: endpoint, HTTPClient: &http.Client{Transport: transport}}
	if err := client.EnsureWatchOnlyWallet(context.Background(), "miner-1"); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestEnsureWatchOnlyWalletLoadsExistingWalletAfterClockRestart(t *testing.T) {
	t.Parallel()
	methods := []string{}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload rpcRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, payload.Method)
		status, body := http.StatusOK, `{"result":{},"error":null}`
		if payload.Method == "createwallet" {
			status = http.StatusInternalServerError
			body = `{"result":null,"error":{"code":-4,"message":"wallet already exists"}}`
		}
		return &http.Response{
			StatusCode: status, Status: http.StatusText(status),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})
	endpoint, err := url.Parse("http://bitcoin:18443")
	if err != nil {
		t.Fatal(err)
	}
	client := &RPCClient{Endpoint: endpoint, HTTPClient: &http.Client{Transport: transport}}
	if err := client.EnsureWatchOnlyWallet(context.Background(), "miner-1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"createwallet", "loadwallet", "getwalletinfo"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
}
