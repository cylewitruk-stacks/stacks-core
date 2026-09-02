package burnchain

import (
	"math"
	"math/big"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// StatusCollector exports one bounded snapshot of the credential-free clock.
type StatusCollector struct {
	Source interface{ Snapshot() (Status, bool) }

	state             *prometheus.Desc
	height            *prometheus.Desc
	generation        *prometheus.Desc
	interval          *prometheus.Desc
	observationTime   *prometheus.Desc
	successTime       *prometheus.Desc
	rpcRetrying       *prometheus.Desc
	branchFingerprint *prometheus.Desc
	chainworkLog2     *prometheus.Desc
	chainTips         *prometheus.Desc
	peers             *prometheus.Desc
}

// NewStatusCollector creates the clock's fixed-cardinality Prometheus collector.
func NewStatusCollector(source interface{ Snapshot() (Status, bool) }) *StatusCollector {
	return &StatusCollector{
		Source:            source,
		state:             prometheus.NewDesc("attacknet_burnchain_clock_state", "Current burnchain-clock state.", []string{"state"}, nil),
		height:            prometheus.NewDesc("attacknet_burnchain_clock_bitcoin_height", "Last Bitcoin height observed by the clock.", nil, nil),
		generation:        prometheus.NewDesc("attacknet_burnchain_clock_policy_generation", "Last immutable policy generation applied by the clock.", nil, nil),
		interval:          prometheus.NewDesc("attacknet_burnchain_clock_interval_seconds", "Requested base burn-block cadence.", []string{"mode", "destination_selection"}, nil),
		observationTime:   prometheus.NewDesc("attacknet_burnchain_clock_last_observation_timestamp_seconds", "Wall time of the latest clock observation.", nil, nil),
		successTime:       prometheus.NewDesc("attacknet_burnchain_clock_last_success_timestamp_seconds", "Wall time of the latest successful Bitcoin height observation.", nil, nil),
		rpcRetrying:       prometheus.NewDesc("attacknet_burnchain_clock_rpc_retrying", "Whether the clock is retrying unavailable Bitcoin RPC.", nil, nil),
		branchFingerprint: prometheus.NewDesc("attacknet_burnchain_clock_branch_fingerprint", "Exact 52-bit fingerprint of the current best-block hash for cohort comparison; full hashes remain in evidence.", nil, nil),
		chainworkLog2:     prometheus.NewDesc("attacknet_burnchain_clock_chainwork_log2", "Base-2 logarithm of cumulative Bitcoin chainwork for bounded visualization; exact chainwork remains in evidence.", nil, nil),
		chainTips:         prometheus.NewDesc("attacknet_burnchain_clock_chain_tips", "Number of locally known Bitcoin branch tips.", nil, nil),
		peers:             prometheus.NewDesc("attacknet_burnchain_clock_connected_peers", "Number of connected Bitcoin peers.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (collector *StatusCollector) Describe(output chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.state, collector.height, collector.generation, collector.interval, collector.observationTime, collector.successTime, collector.rpcRetrying, collector.branchFingerprint, collector.chainworkLog2, collector.chainTips, collector.peers} {
		output <- descriptor
	}
}

// Collect implements prometheus.Collector.
func (collector *StatusCollector) Collect(output chan<- prometheus.Metric) {
	if collector.Source == nil {
		return
	}
	status, observed := collector.Source.Snapshot()
	if !observed {
		return
	}
	output <- prometheus.MustNewConstMetric(collector.state, prometheus.GaugeValue, 1, string(status.State))
	if status.BitcoinHeight != nil {
		output <- prometheus.MustNewConstMetric(collector.height, prometheus.GaugeValue, float64(*status.BitcoinHeight))
	}
	if status.PolicyGeneration != nil {
		output <- prometheus.MustNewConstMetric(collector.generation, prometheus.GaugeValue, float64(*status.PolicyGeneration))
	}
	if status.IntervalSeconds != nil {
		output <- prometheus.MustNewConstMetric(collector.interval, prometheus.GaugeValue, float64(*status.IntervalSeconds), string(status.PolicyMode), string(status.AddressMode))
	}
	if !status.UpdatedAt.IsZero() {
		output <- prometheus.MustNewConstMetric(collector.observationTime, prometheus.GaugeValue, float64(status.UpdatedAt.UnixMilli())/1000)
	}
	if status.LastSuccessAt != nil {
		output <- prometheus.MustNewConstMetric(collector.successTime, prometheus.GaugeValue, float64(status.LastSuccessAt.UnixMilli())/1000)
	}
	retrying := 0.0
	if status.State == "degraded" && status.Detail == "bitcoin-rpc-retry" {
		retrying = 1
	}
	output <- prometheus.MustNewConstMetric(collector.rpcRetrying, prometheus.GaugeValue, retrying)
	if status.ObservationError == "" && status.ChainInfo != nil && fixedHex(status.ChainInfo.BestBlockHash, 64) && fixedHex(status.ChainInfo.Chainwork, 64) {
		if fingerprint, err := strconv.ParseUint(status.ChainInfo.BestBlockHash[:13], 16, 52); err == nil {
			output <- prometheus.MustNewConstMetric(collector.branchFingerprint, prometheus.GaugeValue, float64(fingerprint))
		}
		if chainwork, ok := new(big.Int).SetString(status.ChainInfo.Chainwork, 16); ok && chainwork.Sign() > 0 {
			mantissa := new(big.Float)
			exponent := new(big.Float).SetInt(chainwork).MantExp(mantissa)
			fraction, _ := mantissa.Float64()
			output <- prometheus.MustNewConstMetric(collector.chainworkLog2, prometheus.GaugeValue, float64(exponent)+math.Log2(fraction))
		}
		output <- prometheus.MustNewConstMetric(collector.chainTips, prometheus.GaugeValue, float64(len(status.ChainTips)))
		output <- prometheus.MustNewConstMetric(collector.peers, prometheus.GaugeValue, float64(len(status.Peers)))
	}
}
