package burnchain

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestStatusCollectorExportsBoundedOperationalState(t *testing.T) {
	height, generation, interval := uint64(211), uint64(4), uint64(20)
	recorder := &StatusRecorder{}
	if err := recorder.Write(Status{
		State: "running", BitcoinHeight: &height, PolicyGeneration: &generation,
		PolicyMode: ModeRun, IntervalSeconds: &interval, AddressMode: AddressRoundRobin,
		ChainInfo: &ChainInfo{BestBlockHash: "123456789abcd" + "000000000000000000000000000000000000000000000000000", Chainwork: strings.Repeat("0", 61) + "100"},
		ChainTips: []ChainTip{{Hash: "tip-a"}, {Hash: "tip-b"}}, Peers: []PeerInfo{{ID: 1}},
		UpdatedAt: time.Unix(1_700_000_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewStatusCollector(recorder))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	labels := map[string]map[string]string{}
	for _, family := range families {
		if len(family.Metric) != 1 || family.Metric[0].Gauge == nil {
			continue
		}
		values[family.GetName()] = family.Metric[0].Gauge.GetValue()
		labels[family.GetName()] = map[string]string{}
		for _, label := range family.Metric[0].Label {
			labels[family.GetName()][label.GetName()] = label.GetValue()
		}
	}
	for name, want := range map[string]float64{
		"attacknet_burnchain_clock_bitcoin_height":                 211,
		"attacknet_burnchain_clock_interval_seconds":               20,
		"attacknet_burnchain_clock_last_success_timestamp_seconds": 1_700_000_000,
		"attacknet_burnchain_clock_policy_generation":              4,
		"attacknet_burnchain_clock_rpc_retrying":                   0,
		"attacknet_burnchain_clock_state":                          1,
		"attacknet_burnchain_clock_branch_fingerprint":             0x123456789abcd,
		"attacknet_burnchain_clock_chainwork_log2":                 8,
		"attacknet_burnchain_clock_chain_tips":                     2,
		"attacknet_burnchain_clock_connected_peers":                1,
	} {
		if values[name] != want {
			t.Errorf("%s = %v, want %v", name, values[name], want)
		}
	}
	if labels["attacknet_burnchain_clock_state"]["state"] != "running" || labels["attacknet_burnchain_clock_interval_seconds"]["destination_selection"] != "round-robin" {
		t.Fatalf("bounded labels were not exported: %#v", labels)
	}
}

func TestStatusRecorderCarriesLastSuccessAcrossRPCRetry(t *testing.T) {
	height := uint64(2)
	recorder := &StatusRecorder{}
	succeededAt := time.Unix(100, 0)
	if err := recorder.Write(Status{State: "running", BitcoinHeight: &height, UpdatedAt: succeededAt}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Write(Status{State: "degraded", Detail: "bitcoin-rpc-retry", UpdatedAt: time.Unix(105, 0)}); err != nil {
		t.Fatal(err)
	}
	status, ok := recorder.Snapshot()
	if !ok || status.LastSuccessAt == nil || !status.LastSuccessAt.Equal(succeededAt) {
		t.Fatalf("latest success was lost during retry: %#v", status)
	}
}

func TestIncompleteBranchObservationDoesNotAdvanceSuccessOrBranchMetrics(t *testing.T) {
	height := uint64(2)
	recorder := &StatusRecorder{}
	succeededAt := time.Unix(100, 0)
	if err := recorder.Write(Status{State: "running", BitcoinHeight: &height, UpdatedAt: succeededAt}); err != nil {
		t.Fatal(err)
	}
	failedAt := time.Unix(105, 0)
	if err := recorder.Write(Status{
		State: "running", BitcoinHeight: &height,
		ChainInfo:        &ChainInfo{BestBlockHash: "123456789abcd" + "000000000000000000000000000000000000000000000000000"},
		ObservationError: "peer-info-unavailable", UpdatedAt: failedAt,
	}); err != nil {
		t.Fatal(err)
	}
	status, _ := recorder.Snapshot()
	if status.LastSuccessAt == nil || !status.LastSuccessAt.Equal(succeededAt) {
		t.Fatalf("partial observation advanced success time: %#v", status)
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewStatusCollector(recorder))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "attacknet_burnchain_clock_branch_fingerprint" {
			t.Fatal("partial branch observation exported a branch fingerprint")
		}
	}
}
