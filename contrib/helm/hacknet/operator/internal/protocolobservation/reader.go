package protocolobservation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"sigs.k8s.io/controller-runtime/pkg/client"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/inventory"
)

const (
	defaultRequestTimeout = 3 * time.Second
	maximumMetricsBytes   = 4 << 20
	maximumConcurrency    = 8
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

// IdentityView is the directly verified admitted identity used on both sides
// of metrics collection.
type IdentityView struct {
	NetworkUID      string
	InventoryDigest string
	Namespace       string
	Actors          []attacknetv1beta1.AdmittedActorIdentity
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
	}, nil
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

	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	observedAt := now().UTC()
	actors := make([]ActorSnapshot, 0, len(before.Actors))
	for _, actor := range before.Actors {
		if _, supported := r.endpointResolver().MetricsEndpoint(network.Namespace, actor); !supported {
			continue
		}
		actors = append(actors, ActorSnapshot{Source: Source{
			Actor: actor.Name, Role: actor.Role, PodName: actor.PodName, PodUID: actor.PodUID,
			RuntimeImageID: actor.RuntimeImageID, ServiceName: actor.ServiceName,
			ObservedAt: observedAt, EvidenceClass: EvidenceActorSelfReported,
		}, Error: "metrics collection did not complete"})
	}
	r.collect(ctx, before.Namespace, before.Actors, actors)
	sort.Slice(actors, func(left, right int) bool {
		return actors[left].Source.Actor < actors[right].Source.Actor
	})

	after, err := r.identityReader().Read(ctx, network)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read protocol observation identity after collection: %w", err)
	}
	if after.NetworkUID != before.NetworkUID || after.InventoryDigest != before.InventoryDigest {
		return Snapshot{}, errors.New("StacksNetwork admitted inventory changed during protocol observation")
	}
	if !sameActors(before.Actors, after.Actors) {
		return Snapshot{}, errors.New("protocol observation actor identity changed during collection")
	}
	return Snapshot{
		NetworkUID: before.NetworkUID, InventoryDigest: before.InventoryDigest,
		ObservedAt: observedAt, Actors: actors,
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
