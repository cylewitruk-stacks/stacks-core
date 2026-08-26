package burnchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
)

const maxRPCResponseBytes = 16 << 20

// WalletTransaction describes the fields needed for restart reconciliation.
type WalletTransaction struct {
	// TxID identifies the wallet transaction.
	TxID string
	// Confirmations is zero for an unconfirmed transaction.
	Confirmations int64
	// Abandoned reports whether Bitcoin Core has already released its inputs.
	Abandoned bool
	// Sent distinguishes outbound transactions from received funds.
	Sent bool
}

// Bitcoin exposes the bounded Bitcoin Core operations needed by the clock.
type Bitcoin interface {
	Height(context.Context) (uint64, error)
	Uptime(context.Context) (uint64, error)
	EnsureWatchOnlyWallet(context.Context, string) error
	WalletTransactions(context.Context, string) ([]WalletTransaction, error)
	InMempool(context.Context, string) (bool, error)
	AbandonTransaction(context.Context, string, string) error
	MineBlock(context.Context, string, string) error
}

// RPCClient is a bounded Bitcoin Core JSON-RPC client.
type RPCClient struct {
	// Endpoint is the fixed Bitcoin Core HTTP endpoint.
	Endpoint *url.URL
	// Username is the configured RPC username.
	Username string
	// Password is the configured RPC password.
	Password string
	// HTTPClient applies process-level transport timeouts.
	HTTPClient *http.Client
	requestID  atomic.Uint64
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (rpcErr *rpcError) Error() string {
	return fmt.Sprintf("Bitcoin RPC error %d: %s", rpcErr.Code, rpcErr.Message)
}

// Height returns the canonical regtest block height.
func (client *RPCClient) Height(ctx context.Context) (uint64, error) {
	var height uint64
	return height, client.call(ctx, "", "getblockcount", []any{}, &height)
}

// Uptime returns the Bitcoin Core process uptime in seconds.
func (client *RPCClient) Uptime(ctx context.Context) (uint64, error) {
	var uptime uint64
	return uptime, client.call(ctx, "", "uptime", []any{}, &uptime)
}

// EnsureWatchOnlyWallet idempotently creates or loads one descriptor wallet.
func (client *RPCClient) EnsureWatchOnlyWallet(ctx context.Context, wallet string) error {
	var ignored json.RawMessage
	err := client.call(ctx, "", "createwallet", map[string]any{
		"wallet_name": wallet, "disable_private_keys": true,
		"blank": false, "descriptors": true, "load_on_startup": false,
	}, &ignored)
	if err != nil {
		var remote *rpcError
		if !errors.As(err, &remote) || (remote.Code != -4 && remote.Code != -35) {
			return err
		}
		if loadErr := client.call(ctx, "", "loadwallet", []any{wallet}, &ignored); loadErr != nil {
			if !errors.As(loadErr, &remote) || remote.Code != -35 {
				return loadErr
			}
		}
	}
	return client.call(ctx, wallet, "getwalletinfo", []any{}, &ignored)
}

// WalletTransactions returns unique wallet transactions relevant to reconciliation.
func (client *RPCClient) WalletTransactions(ctx context.Context, wallet string) ([]WalletTransaction, error) {
	var listed []struct {
		TxID string `json:"txid"`
	}
	if err := client.call(ctx, wallet, "listtransactions", []any{"*", 5000, 0, true}, &listed); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	result := make([]WalletTransaction, 0, len(listed))
	for _, item := range listed {
		if item.TxID == "" || seen[item.TxID] {
			continue
		}
		seen[item.TxID] = true
		var transaction struct {
			Confirmations int64 `json:"confirmations"`
			Abandoned     bool  `json:"abandoned"`
			Details       []struct {
				Category string `json:"category"`
			} `json:"details"`
		}
		if err := client.call(ctx, wallet, "gettransaction", []any{item.TxID, true}, &transaction); err != nil {
			return nil, err
		}
		sent := false
		for _, detail := range transaction.Details {
			sent = sent || detail.Category == "send"
		}
		result = append(result, WalletTransaction{TxID: item.TxID, Confirmations: transaction.Confirmations, Abandoned: transaction.Abandoned, Sent: sent})
	}
	return result, nil
}

// InMempool reports whether the transaction remains authoritative.
func (client *RPCClient) InMempool(ctx context.Context, txID string) (bool, error) {
	var ignored json.RawMessage
	err := client.call(ctx, "", "getmempoolentry", []any{txID}, &ignored)
	if err == nil {
		return true, nil
	}
	var remote *rpcError
	if errors.As(err, &remote) && remote.Code == -5 {
		return false, nil
	}
	return false, err
}

// AbandonTransaction releases inputs held by an inactive wallet send.
func (client *RPCClient) AbandonTransaction(ctx context.Context, wallet, txID string) error {
	var ignored json.RawMessage
	return client.call(ctx, wallet, "abandontransaction", []any{txID}, &ignored)
}

// MineBlock mines exactly one block to the supplied address.
func (client *RPCClient) MineBlock(ctx context.Context, wallet, address string) error {
	var hashes []string
	return client.call(ctx, wallet, "generatetoaddress", []any{1, address}, &hashes)
}

func (client *RPCClient) call(ctx context.Context, wallet, method string, params, output any) error {
	if client.Endpoint == nil || client.HTTPClient == nil {
		return fmt.Errorf("Bitcoin RPC endpoint and HTTP client are required")
	}
	payload, err := json.Marshal(rpcRequest{JSONRPC: "1.0", ID: client.requestID.Add(1), Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encode %s request: %w", method, err)
	}
	endpoint := *client.Endpoint
	if wallet != "" {
		endpoint.Path = "/wallet/" + url.PathEscape(wallet)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build %s request: %w", method, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(client.Username, client.Password)
	response, err := client.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("call %s: %w", method, err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxRPCResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", method, err)
	}
	if len(contents) > maxRPCResponseBytes {
		return fmt.Errorf("decode %s response: response exceeds %d bytes", method, maxRPCResponseBytes)
	}
	var envelope rpcResponse
	if err := json.Unmarshal(contents, &envelope); err != nil {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("call %s: HTTP %s: %s", method, response.Status, strconv.Quote(string(contents)))
		}
		return fmt.Errorf("decode %s response: %w", method, err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("call %s: HTTP %s: %s", method, response.Status, strconv.Quote(string(contents)))
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, output); err != nil {
		return fmt.Errorf("decode %s result: %w", method, err)
	}
	return nil
}
