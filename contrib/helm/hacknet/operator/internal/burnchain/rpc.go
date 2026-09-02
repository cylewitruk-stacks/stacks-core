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

// ChainInfo is the canonical Bitcoin branch identity needed by a reorg worker.
type ChainInfo struct {
	Chain         string `json:"chain"`
	Blocks        int64  `json:"blocks"`
	Headers       int64  `json:"headers"`
	BestBlockHash string `json:"bestblockhash"`
	Chainwork     string `json:"chainwork"`
}

// BlockHeader is the bounded header evidence used to identify a branch.
type BlockHeader struct {
	Hash          string `json:"hash"`
	Height        int64  `json:"height"`
	PreviousHash  string `json:"previousblockhash,omitempty"`
	Chainwork     string `json:"chainwork"`
	Confirmations int64  `json:"confirmations"`
}

// ChainTip describes one branch returned by getchaintips.
type ChainTip struct {
	Height    int64  `json:"height"`
	Hash      string `json:"hash"`
	BranchLen int64  `json:"branchlen"`
	Status    string `json:"status"`
}

// PeerInfo is the bounded transport identity returned by getpeerinfo.
type PeerInfo struct {
	ID              int64  `json:"id"`
	Address         string `json:"addr"`
	Inbound         bool   `json:"inbound"`
	ConnectionType  string `json:"connection_type"`
	LastBlock       int64  `json:"last_block"`
	LastTransaction int64  `json:"last_transaction"`
}

// Observer exposes read-only Bitcoin branch and transport observations.
type Observer interface {
	ChainInfo(context.Context) (ChainInfo, error)
	ChainTips(context.Context) ([]ChainTip, error)
	PeerInfo(context.Context) ([]PeerInfo, error)
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

// ChainInfo returns the canonical branch and cumulative work.
func (client *RPCClient) ChainInfo(ctx context.Context) (ChainInfo, error) {
	var result ChainInfo
	return result, client.call(ctx, "", "getblockchaininfo", []any{}, &result)
}

// BlockHash resolves one canonical height.
func (client *RPCClient) BlockHash(ctx context.Context, height int64) (string, error) {
	var result string
	return result, client.call(ctx, "", "getblockhash", []any{height}, &result)
}

// BlockHeader returns verbose header evidence for one hash.
func (client *RPCClient) BlockHeader(ctx context.Context, hash string) (BlockHeader, error) {
	var result BlockHeader
	return result, client.call(ctx, "", "getblockheader", []any{hash, true}, &result)
}

// ChainTips returns all locally known Bitcoin branches.
func (client *RPCClient) ChainTips(ctx context.Context) ([]ChainTip, error) {
	var result []ChainTip
	return result, client.call(ctx, "", "getchaintips", []any{}, &result)
}

// PeerInfo returns bounded identities for currently connected Bitcoin peers.
func (client *RPCClient) PeerInfo(ctx context.Context) ([]PeerInfo, error) {
	var result []PeerInfo
	return result, client.call(ctx, "", "getpeerinfo", []any{}, &result)
}

// InvalidateBlock marks one block and its descendants invalid locally.
func (client *RPCClient) InvalidateBlock(ctx context.Context, hash string) error {
	return client.call(ctx, "", "invalidateblock", []any{hash}, nil)
}

// ReconsiderBlock removes a local invalidity marker. It does not prove which
// branch Bitcoin Core selects afterward.
func (client *RPCClient) ReconsiderBlock(ctx context.Context, hash string) error {
	return client.call(ctx, "", "reconsiderblock", []any{hash}, nil)
}

// GenerateBlocks mines exactly count blocks and returns every generated hash.
func (client *RPCClient) GenerateBlocks(ctx context.Context, wallet, address string, count int32) ([]string, error) {
	var hashes []string
	err := client.call(ctx, wallet, "generatetoaddress", []any{count, address}, &hashes)
	if err == nil && len(hashes) != int(count) {
		return nil, fmt.Errorf("generatetoaddress returned %d hashes, want %d", len(hashes), count)
	}
	return hashes, err
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
