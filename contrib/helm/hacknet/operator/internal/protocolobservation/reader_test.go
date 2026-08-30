package protocolobservation

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

type identitySequence struct {
	mu     sync.Mutex
	values []IdentityView
}

func (s *identitySequence) Read(context.Context, *attacknetv1beta1.StacksNetwork) (IdentityView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.values[0]
	if len(s.values) > 1 {
		s.values = s.values[1:]
	}
	return value, nil
}

type httpDoer func(*http.Request) (*http.Response, error)

func (function httpDoer) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type endpointMap map[string]string

func (values endpointMap) MetricsEndpoint(_ string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool) {
	value, ok := values[actor.Name]
	return value, ok
}

type endpointContract struct{ metrics, info map[string]string }

type replacingPolicyReader struct {
	client.Reader
	mu   sync.Mutex
	gets int
}

func (r *replacingPolicyReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if policy, ok := object.(*attacknetv1beta1.BurnchainPolicy); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.gets++
		if r.gets > 1 {
			policy.UID = "replacement-policy-uid"
		}
	}
	return nil
}

func (values endpointContract) MetricsEndpoint(_ string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool) {
	value, ok := values.metrics[actor.Name]
	return value, ok
}

func (values endpointContract) ChainInfoEndpoint(_ string, actor attacknetv1beta1.AdmittedActorIdentity) (string, bool) {
	value, ok := values.info[actor.Name]
	return value, ok
}

func TestReaderCollectsMetricsBetweenStableIdentityChecks(t *testing.T) {
	actors := []attacknetv1beta1.AdmittedActorIdentity{
		{Name: "signer-1", Role: "signer", ServiceName: "network-signer-1", PodName: "signer-1-0", PodUID: "pod-signer", RuntimeImageID: strings.Repeat("a", 64)},
		{Name: "miner-1", Role: "miner", ServiceName: "network-miner-1", PodName: "miner-1-0", PodUID: "pod-miner", RuntimeImageID: strings.Repeat("b", 64)},
	}
	view := IdentityView{NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", Namespace: "test", Actors: actors}
	reader := &Reader{
		Identities: &identitySequence{values: []IdentityView{view, view}},
		Endpoints:  endpointMap{"miner-1": "http://metrics/miner", "signer-1": "http://metrics/signer"},
		Now:        func() time.Time { return time.Unix(100, 0).UTC() },
		HTTP: httpDoer(func(request *http.Request) (*http.Response, error) {
			body := "# TYPE stacks_node_stacks_tip_height gauge\nstacks_node_stacks_tip_height 12\n"
			if strings.HasSuffix(request.URL.Path, "signer") {
				body = "# TYPE stacks_signer_registered_for_current_reward_cycle gauge\nstacks_signer_registered_for_current_reward_cycle 1\n"
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		}),
	}
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid")}}
	snapshot, err := reader.Read(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete() || snapshot.InventoryDigest != view.InventoryDigest || len(snapshot.Actors) != 2 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if snapshot.Actors[0].Source.Actor != "miner-1" || snapshot.Actors[0].Source.PodUID != "pod-miner" {
		t.Fatalf("actors are not identity-bound and sorted: %#v", snapshot.Actors)
	}
	if value, err := snapshot.Actors[0].Scalar("stacks_node_stacks_tip_height"); err != nil || value != 12 {
		t.Fatalf("tip height = %v, %v", value, err)
	}
}

func TestReaderUsesOneCollectionBoundaryForActorMetrics(t *testing.T) {
	actor := attacknetv1beta1.AdmittedActorIdentity{
		Name: "miner-1", Role: "miner", ServiceName: "network-miner-1",
		PodName: "miner-1-0", PodUID: "pod-miner", RuntimeImageID: strings.Repeat("a", 64),
	}
	view := IdentityView{
		NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", Namespace: "test",
		Actors: []attacknetv1beta1.AdmittedActorIdentity{actor},
	}
	base := time.Unix(100, 0).UTC()
	tick := 0
	reader := &Reader{
		Identities: &identitySequence{values: []IdentityView{view, view}},
		Endpoints:  endpointMap{"miner-1": "http://metrics/miner"},
		Now: func() time.Time {
			observed := base.Add(time.Duration(tick) * time.Second)
			tick++
			return observed
		},
		HTTP: httpDoer(func(*http.Request) (*http.Response, error) {
			body := "# TYPE stacks_node_stacks_tip_height gauge\nstacks_node_stacks_tip_height 12\n"
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		}),
	}
	network := &attacknetv1beta1.StacksNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("network-uid")},
	}
	snapshot, err := reader.Read(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	if tick < 2 {
		t.Fatal("test did not exercise distinct start and completion clock reads")
	}
	if len(snapshot.Actors) != 1 || !snapshot.Actors[0].Source.ObservedAt.Equal(snapshot.ObservedAt) {
		t.Fatalf("actor source and snapshot use different collection boundaries: %#v", snapshot)
	}
	if !snapshot.ObservedAt.Equal(base) {
		t.Fatalf("snapshot boundary = %s, want collection start %s", snapshot.ObservedAt, base)
	}
}

func TestReaderReturnsPartialSnapshotForEndpointFailure(t *testing.T) {
	actor := attacknetv1beta1.AdmittedActorIdentity{Name: "miner-1", Role: "miner", ServiceName: "miner", PodName: "miner-0", PodUID: "pod", RuntimeImageID: strings.Repeat("a", 64)}
	view := IdentityView{NetworkUID: "uid", InventoryDigest: "digest", Namespace: "test", Actors: []attacknetv1beta1.AdmittedActorIdentity{actor}}
	reader := &Reader{
		Identities: &identitySequence{values: []IdentityView{view, view}},
		Endpoints:  endpointMap{"miner-1": "http://metrics/miner"},
		HTTP: httpDoer(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		}),
	}
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("uid")}}
	snapshot, err := reader.Read(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Complete() || len(snapshot.Actors) != 1 || !strings.Contains(snapshot.Actors[0].Error, "HTTP 503") {
		t.Fatalf("endpoint failure was not retained: %#v", snapshot)
	}
}

func TestReaderJoinsStacksAndBitcoinViewsToAdmittedTopology(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	actors := []attacknetv1beta1.AdmittedActorIdentity{
		{Name: "bitcoin-a", Role: "burnchain", ServiceName: "bitcoin-a", PodName: "bitcoin-a-0", PodUID: "btc-pod", StatefulSetUID: "btc-set", RuntimeImageID: "sha256:" + strings.Repeat("a", 64)},
		{Name: "follower-a", Role: "follower", ServiceName: "follower-a", PodName: "follower-a-0", PodUID: "stacks-pod", RuntimeImageID: "sha256:" + strings.Repeat("b", 64)},
	}
	topology := &attacknetv1beta1.AdmittedBurnchainTopology{
		Digest: "sha256:" + strings.Repeat("c", 64), ObservedGeneration: 1,
		Nodes:    []attacknetv1beta1.AdmittedBitcoinNode{{Name: "bitcoin-a", PolicyRef: "policy-a", PolicyUID: "policy-uid"}},
		Bindings: []attacknetv1beta1.BurnchainActorBinding{{Actor: "follower-a", BitcoinNodeRef: "bitcoin-a"}},
	}
	view := IdentityView{NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", Namespace: "test", Actors: actors, BurnchainTopology: topology}
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.BurnchainPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "test", UID: "policy-uid", Generation: 1},
		Spec: attacknetv1beta1.BurnchainPolicySpec{NetworkRef: "network", BitcoinNodeRef: "bitcoin-a"}, Status: attacknetv1beta1.BurnchainPolicyStatus{
			ObservedGeneration: 1, Phase: "Ready",
			AdmittedNetworkUID: "network-uid", AdmittedBitcoinUID: "btc-set", AdmittedBitcoinImageID: "sha256:" + strings.Repeat("a", 64),
			ObservedHeight: 250, ObservedHeaders: 250, LastBlockHash: strings.Repeat("1", 64), ObservedChainwork: strings.Repeat("2", 64),
			BitcoinObservationAt: &metav1.Time{Time: now}, ObservedPeers: []attacknetv1beta1.BurnchainPeerStatus{{ID: 1, Address: "bitcoin-b:18444"}},
		}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	reader := &Reader{APIReader: kube,
		Identities: &identitySequence{values: []IdentityView{view, view}}, Now: func() time.Time { return now },
		Endpoints: endpointContract{metrics: map[string]string{"follower-a": "http://actor/metrics"}, info: map[string]string{"follower-a": "http://actor/v2/info"}},
		HTTP: httpDoer(func(request *http.Request) (*http.Response, error) {
			body := "# TYPE stacks_node_stacks_tip_height gauge\nstacks_node_stacks_tip_height 12\n"
			if request.URL.Path == "/v2/info" {
				body = `{"burn_block_height":250,"pox_consensus":"` + strings.Repeat("3", 40) + `","stacks_tip_height":12,"stacks_tip":"` + strings.Repeat("4", 64) + `","stacks_tip_consensus_hash":"` + strings.Repeat("5", 40) + `","is_fully_synced":true}`
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		})}
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid"}}
	snapshot, err := reader.Read(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Actors[0].ChainView == nil || snapshot.Actors[0].ChainView.BurnBlockHeight != 250 {
		t.Fatalf("Stacks chain view not retained: %#v", snapshot.Actors[0])
	}
	bitcoin, ok := snapshot.BitcoinActor("bitcoin-a")
	if !ok || bitcoin.Error != "" || bitcoin.BestBlockHash != strings.Repeat("1", 64) || len(bitcoin.Peers) != 1 {
		t.Fatalf("Bitcoin view not identity-bound: %#v", bitcoin)
	}
	if err := kube.Delete(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	replacement := policy.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-policy-uid"
	if err := kube.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	reader.Identities = &identitySequence{values: []IdentityView{view, view}}
	if _, err = reader.Read(context.Background(), network); err == nil || !strings.Contains(err.Error(), "admitted identity changed") {
		t.Fatalf("replacement policy was not rejected against the admitted graph: %v", err)
	}
}

func TestReaderRejectsBurnchainPolicyReplacementDuringCollection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	bitcoin := attacknetv1beta1.AdmittedActorIdentity{
		Name: "bitcoin-a", Role: "burnchain", StatefulSetUID: "btc-set",
		RuntimeImageID: "sha256:" + strings.Repeat("a", 64),
	}
	topology := &attacknetv1beta1.AdmittedBurnchainTopology{
		Digest: "sha256:" + strings.Repeat("c", 64), ObservedGeneration: 1,
		Nodes: []attacknetv1beta1.AdmittedBitcoinNode{{Name: "bitcoin-a", PolicyRef: "policy-a", PolicyUID: "policy-uid"}},
	}
	view := IdentityView{
		NetworkUID: "network-uid", InventoryDigest: "sha256:inventory", Namespace: "test",
		Actors: []attacknetv1beta1.AdmittedActorIdentity{bitcoin}, BurnchainTopology: topology,
	}
	scheme := runtime.NewScheme()
	if err := attacknetv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &attacknetv1beta1.BurnchainPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "test", UID: "policy-uid", Generation: 1},
		Spec:       attacknetv1beta1.BurnchainPolicySpec{NetworkRef: "network", BitcoinNodeRef: "bitcoin-a"},
		Status: attacknetv1beta1.BurnchainPolicyStatus{
			ObservedGeneration: 1, Phase: "Ready", AdmittedNetworkUID: "network-uid",
			AdmittedBitcoinUID: "btc-set", AdmittedBitcoinImageID: bitcoin.RuntimeImageID,
			ObservedHeight: 250, ObservedHeaders: 250, LastBlockHash: strings.Repeat("1", 64),
			ObservedChainwork: strings.Repeat("2", 64), BitcoinObservationAt: &metav1.Time{Time: now},
		},
	}
	direct := &replacingPolicyReader{Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()}
	reader := &Reader{
		APIReader: direct, Identities: &identitySequence{values: []IdentityView{view, view}},
		Now: func() time.Time { return now },
	}
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: "network-uid"}}
	if _, err := reader.Read(context.Background(), network); err == nil || !strings.Contains(err.Error(), "identity changed during collection") {
		t.Fatalf("BurnchainPolicy replacement during observation was accepted: %v", err)
	}
}

func TestReaderCollectsStacksChainViewsConcurrently(t *testing.T) {
	identities := []attacknetv1beta1.AdmittedActorIdentity{
		{Name: "follower-a", Role: "follower"},
		{Name: "follower-b", Role: "follower"},
	}
	actors := []ActorSnapshot{
		{Source: Source{Actor: "follower-a"}},
		{Source: Source{Actor: "follower-b"}},
	}
	started := make(chan struct{}, len(actors))
	release := make(chan struct{})
	go func() {
		for range actors {
			<-started
		}
		close(release)
	}()
	reader := &Reader{
		Endpoints: endpointContract{info: map[string]string{
			"follower-a": "http://actor-a/v2/info",
			"follower-b": "http://actor-b/v2/info",
		}},
		HTTP: httpDoer(func(request *http.Request) (*http.Response, error) {
			started <- struct{}{}
			select {
			case <-release:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
			body := `{"burn_block_height":250,"pox_consensus":"` + strings.Repeat("3", 40) + `","stacks_tip_height":12,"stacks_tip":"` + strings.Repeat("4", 64) + `","stacks_tip_consensus_hash":"` + strings.Repeat("5", 40) + `","is_fully_synced":true}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reader.collectChainViews(ctx, "test", identities, actors)
	for _, actor := range actors {
		if actor.ChainView == nil || actor.ChainError != "" {
			t.Fatalf("concurrent chain observation was not retained: %#v", actor)
		}
	}
}

func TestReaderDoesNotReuseMetricsConnectionsAcrossObservations(t *testing.T) {
	actor := attacknetv1beta1.AdmittedActorIdentity{Name: "miner-1", Role: "miner"}
	closed := false
	reader := &Reader{
		Endpoints: endpointMap{"miner-1": "http://metrics/miner"},
		HTTP: httpDoer(func(request *http.Request) (*http.Response, error) {
			closed = request.Close
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("# TYPE sample gauge\nsample 1\n")),
				Header:     http.Header{},
			}, nil
		}),
	}
	if _, err := reader.readActor(context.Background(), "test", actor); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("metrics request allowed a connection to outlive its identity-bound observation")
	}
}

func TestReaderRejectsIdentityChangeDuringCollection(t *testing.T) {
	actor := attacknetv1beta1.AdmittedActorIdentity{Name: "miner-1", Role: "miner", ServiceName: "miner", PodName: "miner-0", PodUID: "old", RuntimeImageID: strings.Repeat("a", 64)}
	before := IdentityView{NetworkUID: "uid", InventoryDigest: "old", Namespace: "test", Actors: []attacknetv1beta1.AdmittedActorIdentity{actor}}
	after := before
	after.InventoryDigest = "new"
	reader := &Reader{
		Identities: &identitySequence{values: []IdentityView{before, after}},
		Endpoints:  endpointMap{"miner-1": "http://metrics/miner"},
		HTTP: httpDoer(func(*http.Request) (*http.Response, error) {
			body := "# TYPE stacks_node_stacks_tip_height gauge\nstacks_node_stacks_tip_height 12\n"
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		}),
	}
	network := &attacknetv1beta1.StacksNetwork{ObjectMeta: metav1.ObjectMeta{Name: "network", Namespace: "test", UID: types.UID("uid")}}
	if _, err := reader.Read(context.Background(), network); err == nil || !strings.Contains(err.Error(), "changed during") {
		t.Fatalf("identity transition was accepted: %v", err)
	}
}

func TestActorSnapshotSumRequiresMatchingBoundedLabels(t *testing.T) {
	body := `# TYPE stacks_signer_policy_evaluations counter
stacks_signer_policy_evaluations{classification="proceed",action="continue"} 7
stacks_signer_policy_evaluations{classification="unavailable",action="reject"} 2
`
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	actor := ActorSnapshot{Source: Source{Actor: "signer-1"}, Families: families}
	value, err := actor.Sum("stacks_signer_policy_evaluations", map[string]string{"classification": "unavailable"})
	if err != nil || value != 2 {
		t.Fatalf("sum = %v, %v", value, err)
	}
	if _, err := actor.Sum("stacks_signer_policy_evaluations", map[string]string{"classification": "missing"}); err == nil {
		t.Fatal("missing label set was accepted")
	}
}
