package protocolobservation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/burnchaintopology"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

const (
	defaultRequestTimeout = 3 * time.Second
	maximumMetricsBytes   = 4 << 20
	maximumChainInfoBytes = 1 << 20
	maximumConcurrency    = 8
	maximumObservationAge = 30 * time.Second
)

// HTTPDoer is the bounded HTTP boundary used to read actor metrics.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// EndpointResolver maps one admitted actor to its metrics endpoint. Production
// uses same-namespace Service DNS; tests can inject loopback endpoints.
type EndpointResolver interface {
	MetricsEndpoint(namespace string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool)
}

// ChainEndpointResolver maps one admitted Stacks actor to /v2/info.
type ChainEndpointResolver interface {
	ChainInfoEndpoint(namespace string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool)
}

// IdentityView is the directly verified admitted identity used on both sides
// of metrics collection.
type IdentityView struct {
	NetworkUID        string
	InventoryDigest   string
	Namespace         string
	Actors            []attacknetv1beta1.AdmittedActorIdentity
	BurnchainTopology *attacknetv1beta1.AdmittedBurnchainTopology
}

// IdentityReader supplies uncached, live admitted identities.
type IdentityReader interface {
	Read(context.Context, *attacknetv1beta1.StacksNetwork) (IdentityView, error)
}

// KubernetesIdentityReader validates published inventory against live Pods.
type KubernetesIdentityReader struct {
	Reader client.Reader
}

// Read returns the current complete identity view.
func (r KubernetesIdentityReader) Read(ctx context.Context, network *attacknetv1beta1.StacksNetwork) (IdentityView, error) {
	if r.Reader == nil {
		return IdentityView{}, errors.New("uncached Kubernetes API reader is required")
	}
	live, err := inventory.ReadBetaLiveView(ctx, r.Reader, client.ObjectKeyFromObject(network))
	if err != nil {
		return IdentityView{}, err
	}
	if live.Network.UID != network.UID {
		return IdentityView{}, errors.New("StacksNetwork identity changed")
	}
	published, err := inventory.BetaPublished(live.Network)
	if err != nil {
		return IdentityView{}, fmt.Errorf("read admitted inventory: %w", err)
	}
	if differences := inventory.BetaCompareLive(published, live.Network, live.Pods, nil); len(differences) != 0 {
		return IdentityView{}, fmt.Errorf("admitted inventory is not live: %s", differences[0].Message)
	}
	return IdentityView{
		NetworkUID: string(live.Network.UID), InventoryDigest: published.Digest,
		Namespace: live.Network.Namespace, Actors: published.Actors,
		BurnchainTopology: published.BurnchainTopology,
	}, nil
}

// ChainInfoEndpoint returns the standard Stacks node /v2/info endpoint.
func (ServiceEndpointResolver) ChainInfoEndpoint(namespace string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool) {
	switch actor.Role {
	case "miner", "follower", "companion", "adversary":
		return fmt.Sprintf("http://%s.%s.svc:20443/v2/info", actor.ServiceName, namespace), true
	default:
		return "", false
	}
}

// ServiceEndpointResolver resolves the standard Stacks node and signer ports.
type ServiceEndpointResolver struct{}

// MetricsEndpoint returns the identity-bound actor Service endpoint.
func (ServiceEndpointResolver) MetricsEndpoint(namespace string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool) {
	port := 0
	switch actor.Role {
	case "signer":
		port = 31000
	case "miner", "follower", "companion", "adversary":
		port = 20446
	default:
		return "", false
	}
	return fmt.Sprintf("http://%s.%s.svc:%d/metrics", actor.ServiceName, namespace, port), true
}

// Reader collects actor metrics between two uncached identity checks.
type Reader struct {
	APIReader  client.Reader
	Identities IdentityReader
	HTTP       HTTPDoer
	Endpoints  EndpointResolver
	Now        func() time.Time
	Timeout    time.Duration
}

// Read returns a partial snapshot when an enrolled metrics endpoint is
// unavailable. Kubernetes identity ambiguity is returned as an error.
func (r *Reader) Read(ctx context.Context, network *attacknetv1beta1.StacksNetwork) (Snapshot, error) {
	if r == nil || (r.APIReader == nil && r.Identities == nil) {
		return Snapshot{}, errors.New("protocol observations require an uncached Kubernetes API reader")
	}
	if network == nil || network.Namespace == "" || network.Name == "" || network.UID == "" {
		return Snapshot{}, errors.New("protocol observations require a named, identified StacksNetwork")
	}
	before, err := r.identityReader().Read(ctx, network)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read protocol observation identity before collection: %w", err)
	}
	if before.NetworkUID != string(network.UID) {
		return Snapshot{}, errors.New("StacksNetwork identity changed before protocol observation")
	}

	startedAt := r.now()
	actors := make([]ActorSnapshot, 0, len(before.Actors))
	for _, actor := range before.Actors {
		if _, supported := r.endpointResolver().MetricsEndpoint(network.Namespace, actor); !supported {
			continue
		}
		actors = append(actors, ActorSnapshot{Source: Source{
			Actor: actor.Name, Role: actor.Role, PodName: actor.PodName, PodUID: actor.PodUID,
			RuntimeImageID: actor.RuntimeImageID, ServiceName: actor.ServiceName,
			ObservedAt: startedAt, EvidenceClass: EvidenceActorSelfReported,
		}, Error: "metrics collection did not complete"})
	}
	r.collect(ctx, before.Namespace, before.Actors, actors)
	r.collectChainViews(ctx, before.Namespace, before.Actors, actors)
	sort.Slice(actors, func(left, right int) bool {
		return actors[left].Source.Actor < actors[right].Source.Actor
	})

	bitcoin := r.collectBitcoin(ctx, network.Namespace, network.Name, before, r.now())
	after, err := r.identityReader().Read(ctx, network)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read protocol observation identity after collection: %w", err)
	}
	if after.NetworkUID != before.NetworkUID || after.InventoryDigest != before.InventoryDigest ||
		!sameBurnchainTopology(before.BurnchainTopology, after.BurnchainTopology) {
		return Snapshot{}, errors.New("StacksNetwork admitted inventory changed during protocol observation")
	}
	if !sameActors(before.Actors, after.Actors) {
		return Snapshot{}, errors.New("protocol observation actor identity changed during collection")
	}
	if err := r.verifyBitcoinPolicyIdentities(ctx, network.Name, before); err != nil {
		return Snapshot{}, fmt.Errorf("verify burnchain policy identity after collection: %w", err)
	}
	return Snapshot{
		NetworkUID: before.NetworkUID, InventoryDigest: before.InventoryDigest,
		// All actor metric sources use the collection-start boundary. Retaining
		// that same timestamp on the enclosing snapshot makes the cohort an
		// explicit identity-bound observation and ages it conservatively.
		ObservedAt: startedAt, Actors: actors, Bitcoin: bitcoin,
		BurnchainTopology: before.BurnchainTopology,
	}, nil
}

func (r *Reader) collect(ctx context.Context, namespace string, identities []attacknetv1beta1.AdmittedActorIdentity, actors []ActorSnapshot) {
	byName := make(map[string]attacknetv1beta1.AdmittedActorIdentity, len(identities))
	for _, identity := range identities {
		byName[identity.Name] = identity
	}
	type result struct {
		index    int
		families map[string]*dto.MetricFamily
		err      error
	}
	jobs := make(chan int)
	results := make(chan result, len(actors))
	workers := maximumConcurrency
	if len(actors) < workers {
		workers = len(actors)
	}
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				identity := byName[actors[index].Source.Actor]
				families, err := r.readActor(ctx, namespace, identity)
				results <- result{index: index, families: families, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range actors {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()
	for result := range results {
		if result.err != nil {
			actors[result.index].Error = result.err.Error()
			continue
		}
		actors[result.index].Families = result.families
		actors[result.index].Error = ""
	}
}

func (r *Reader) collectChainViews(ctx context.Context, namespace string, identities []attacknetv1beta1.AdmittedActorIdentity, actors []ActorSnapshot) {
	resolver, ok := r.endpointResolver().(ChainEndpointResolver)
	if !ok {
		return
	}
	byName := make(map[string]attacknetv1beta1.AdmittedActorIdentity, len(identities))
	for _, identity := range identities {
		byName[identity.Name] = identity
	}
	type result struct {
		index      int
		view       *StacksChainView
		observedAt time.Time
		err        error
	}
	indexes := make([]int, 0, len(actors))
	for index := range actors {
		if _, supported := resolver.ChainInfoEndpoint(namespace, byName[actors[index].Source.Actor]); supported {
			indexes = append(indexes, index)
		}
	}
	if len(indexes) == 0 {
		return
	}
	jobs := make(chan int)
	results := make(chan result, len(indexes))
	workers := min(maximumConcurrency, len(indexes))
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				identity := byName[actors[index].Source.Actor]
				endpoint, _ := resolver.ChainInfoEndpoint(namespace, identity)
				view, err := r.readChainView(ctx, endpoint)
				results <- result{index: index, view: view, observedAt: r.now(), err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, index := range indexes {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()
	for result := range results {
		if result.err != nil {
			actors[result.index].ChainError = result.err.Error()
			continue
		}
		actors[result.index].ChainView = result.view
		actors[result.index].ChainObservedAt = result.observedAt
		actors[result.index].ChainError = ""
	}
}

func (r *Reader) readChainView(ctx context.Context, endpoint string) (*StacksChainView, error) {
	var value struct {
		BurnBlockHeight     uint64 `json:"burn_block_height"`
		BurnConsensusHash   string `json:"pox_consensus"`
		StacksTipHeight     uint64 `json:"stacks_tip_height"`
		StacksTip           string `json:"stacks_tip"`
		StacksConsensusHash string `json:"stacks_tip_consensus_hash"`
		FullySynced         bool   `json:"is_fully_synced"`
	}
	if err := r.readJSON(ctx, endpoint, &value); err != nil {
		return nil, err
	}
	if !fixedHex(value.BurnConsensusHash, 40) || !fixedHex(value.StacksTip, 64) || !fixedHex(value.StacksConsensusHash, 40) {
		return nil, errors.New("Stacks chain view contains an invalid hash")
	}
	return &StacksChainView{
		BurnBlockHeight: value.BurnBlockHeight, BurnConsensusHash: value.BurnConsensusHash,
		StacksTipHeight: value.StacksTipHeight, StacksTip: value.StacksTip,
		StacksConsensusHash: value.StacksConsensusHash, FullySynced: value.FullySynced,
	}, nil
}

func (r *Reader) collectBitcoin(ctx context.Context, namespace, networkName string, identity IdentityView, observedAt time.Time) []BitcoinSnapshot {
	if identity.BurnchainTopology == nil {
		return nil
	}
	byName := make(map[string]attacknetv1beta1.AdmittedActorIdentity, len(identity.Actors))
	for _, actor := range identity.Actors {
		byName[actor.Name] = actor
	}
	result := make([]BitcoinSnapshot, 0, len(identity.BurnchainTopology.Nodes))
	for _, node := range identity.BurnchainTopology.Nodes {
		actor, exists := byName[node.Name]
		observation := BitcoinSnapshot{PolicyName: node.PolicyRef, TopologyDigest: identity.BurnchainTopology.Digest}
		if exists {
			observation.Source = Source{Actor: actor.Name, Role: actor.Role, PodName: actor.PodName, PodUID: actor.PodUID,
				RuntimeImageID: actor.RuntimeImageID, ServiceName: actor.ServiceName, ObservedAt: observedAt,
				EvidenceClass: EvidenceActorSelfReported}
		}
		if !exists || r.APIReader == nil {
			observation.Error = "Bitcoin observation identity is unavailable"
			result = append(result, observation)
			continue
		}
		policy := &attacknetv1beta1.BurnchainPolicy{}
		if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: node.PolicyRef}, policy); err != nil {
			observation.Error = "BurnchainPolicy observation is unavailable"
			result = append(result, observation)
			continue
		}
		if policy.Status.BitcoinObservationAt != nil {
			observation.Source.ObservedAt = policy.Status.BitcoinObservationAt.Time.UTC()
		}
		if !policyMatchesIdentity(policy, identity.BurnchainTopology, node, identity.NetworkUID, actor, networkName) {
			observation.Error = "BurnchainPolicy admitted identity differs"
		} else if policy.Status.BitcoinObservationAt == nil || observedAt.Sub(policy.Status.BitcoinObservationAt.Time) > maximumObservationAge ||
			policy.Status.BitcoinObservationAt.Time.After(observedAt.Add(5*time.Second)) {
			observation.Error = "Bitcoin observation is stale"
		} else if policy.Status.BitcoinObservationError != "" || !fixedHex(policy.Status.LastBlockHash, 64) || !fixedHex(policy.Status.ObservedChainwork, 64) {
			observation.Error = "Bitcoin branch observation is incomplete"
		} else {
			observation.Height, observation.Headers = policy.Status.ObservedHeight, policy.Status.ObservedHeaders
			observation.BestBlockHash, observation.Chainwork = policy.Status.LastBlockHash, policy.Status.ObservedChainwork
			observation.ChainTips = append([]attacknetv1beta1.BurnchainChainTipStatus(nil), policy.Status.ObservedChainTips...)
			observation.Peers = append([]attacknetv1beta1.BurnchainPeerStatus(nil), policy.Status.ObservedPeers...)
		}
		result = append(result, observation)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Source.Actor < result[right].Source.Actor })
	return result
}

// verifyBitcoinPolicyIdentities closes the direct-read bracket around every
// policy-backed Bitcoin observation. StacksNetwork status can briefly retain
// an old policy UID while a policy is being replaced, so a second direct read
// is required in addition to the admitted-topology comparison.
func (r *Reader) verifyBitcoinPolicyIdentities(ctx context.Context, networkName string, identity IdentityView) error {
	if identity.BurnchainTopology == nil {
		return nil
	}
	if r.APIReader == nil {
		return errors.New("uncached Kubernetes API reader is required for Bitcoin observations")
	}
	actors := make(map[string]attacknetv1beta1.AdmittedActorIdentity, len(identity.Actors))
	for _, actor := range identity.Actors {
		actors[actor.Name] = actor
	}
	for _, node := range identity.BurnchainTopology.Nodes {
		actor, exists := actors[node.Name]
		if !exists {
			return fmt.Errorf("Bitcoin actor %q is absent from the admitted inventory", node.Name)
		}
		policy := &attacknetv1beta1.BurnchainPolicy{}
		if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: node.PolicyRef}, policy); err != nil {
			return fmt.Errorf("read BurnchainPolicy %q: %w", node.PolicyRef, err)
		}
		if !policyMatchesIdentity(policy, identity.BurnchainTopology, node, identity.NetworkUID, actor, networkName) {
			return fmt.Errorf("BurnchainPolicy %q admitted identity changed during collection", node.PolicyRef)
		}
	}
	return nil
}

func policyMatchesIdentity(
	policy *attacknetv1beta1.BurnchainPolicy,
	topology *attacknetv1beta1.AdmittedBurnchainTopology,
	node attacknetv1beta1.AdmittedBitcoinNode,
	networkUID string,
	actor attacknetv1beta1.AdmittedActorIdentity,
	networkName string,
) bool {
	return burnchaintopology.VerifyPolicyIdentity(topology, networkName, node.Name, policy) == nil &&
		policy.Status.ObservedGeneration == policy.Generation && policy.Status.Phase == "Ready" &&
		policy.Status.AdmittedNetworkUID == networkUID && policy.Status.AdmittedBitcoinUID == actor.StatefulSetUID &&
		policy.Status.AdmittedBitcoinImageID == actor.RuntimeImageID
}

func (r *Reader) readJSON(ctx context.Context, endpoint string, output any) error {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Close = true
	response, err := r.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("chain info endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumChainInfoBytes+1))
	if err != nil {
		return fmt.Errorf("read chain info: %w", err)
	}
	if len(body) > maximumChainInfoBytes {
		return errors.New("chain info response exceeds 1 MiB")
	}
	if err := json.Unmarshal(body, output); err != nil {
		return fmt.Errorf("decode chain info: %w", err)
	}
	return nil
}

func fixedHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range strings.ToLower(value) {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func (r *Reader) readActor(ctx context.Context, namespace string, actor attacknetv1beta1.AdmittedActorIdentity) (map[string]*dto.MetricFamily, error) {
	endpoint, ok := r.endpointResolver().MetricsEndpoint(namespace, actor)
	if !ok {
		return nil, fmt.Errorf("actor role %s has no metrics contract", actor.Role)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// Every assertion sample must traverse the current Service path. Reusing a
	// connection would hide Service withdrawal and could outlive the identity
	// checks that bracket this observation.
	request.Close = true
	request.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeTextPlain)))
	response, err := r.httpClient().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumMetricsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Prometheus metrics: %w", err)
	}
	if len(body) > maximumMetricsBytes {
		return nil, errors.New("metrics response exceeds 4 MiB")
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decode Prometheus metrics: %w", err)
	}
	return families, nil
}

func (r *Reader) identityReader() IdentityReader {
	if r.Identities != nil {
		return r.Identities
	}
	return KubernetesIdentityReader{Reader: r.APIReader}
}

func (r *Reader) endpointResolver() EndpointResolver {
	if r.Endpoints != nil {
		return r.Endpoints
	}
	return ServiceEndpointResolver{}
}

func (r *Reader) httpClient() HTTPDoer {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Transport: http.DefaultTransport}
}

func (r *Reader) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func sameActors(left, right []attacknetv1beta1.AdmittedActorIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]attacknetv1beta1.AdmittedActorIdentity(nil), left...)
	rightCopy := append([]attacknetv1beta1.AdmittedActorIdentity(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i].Name < leftCopy[j].Name })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i].Name < rightCopy[j].Name })
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func sameBurnchainTopology(left, right *attacknetv1beta1.AdmittedBurnchainTopology) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.SchemaVersion == right.SchemaVersion && left.Digest == right.Digest &&
		left.ObservedGeneration == right.ObservedGeneration
}
