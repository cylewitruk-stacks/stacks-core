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
	"k8s.io/apimachinery/pkg/types"

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
