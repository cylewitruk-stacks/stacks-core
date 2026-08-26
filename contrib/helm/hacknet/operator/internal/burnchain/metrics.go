package burnchain

import "github.com/prometheus/client_golang/prometheus"

// StatusCollector exports one bounded snapshot of the credential-free clock.
type StatusCollector struct {
	Source interface{ Snapshot() (Status, bool) }

	state           *prometheus.Desc
	height          *prometheus.Desc
	generation      *prometheus.Desc
	interval        *prometheus.Desc
	observationTime *prometheus.Desc
	successTime     *prometheus.Desc
	rpcRetrying     *prometheus.Desc
}

// NewStatusCollector creates the clock's fixed-cardinality Prometheus collector.
func NewStatusCollector(source interface{ Snapshot() (Status, bool) }) *StatusCollector {
	return &StatusCollector{
		Source:          source,
		state:           prometheus.NewDesc("attacknet_burnchain_clock_state", "Current burnchain-clock state.", []string{"state"}, nil),
		height:          prometheus.NewDesc("attacknet_burnchain_clock_bitcoin_height", "Last Bitcoin height observed by the clock.", nil, nil),
		generation:      prometheus.NewDesc("attacknet_burnchain_clock_policy_generation", "Last immutable policy generation applied by the clock.", nil, nil),
		interval:        prometheus.NewDesc("attacknet_burnchain_clock_interval_seconds", "Requested base burn-block cadence.", []string{"mode", "destination_selection"}, nil),
		observationTime: prometheus.NewDesc("attacknet_burnchain_clock_last_observation_timestamp_seconds", "Wall time of the latest clock observation.", nil, nil),
		successTime:     prometheus.NewDesc("attacknet_burnchain_clock_last_success_timestamp_seconds", "Wall time of the latest successful Bitcoin height observation.", nil, nil),
		rpcRetrying:     prometheus.NewDesc("attacknet_burnchain_clock_rpc_retrying", "Whether the clock is retrying unavailable Bitcoin RPC.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (collector *StatusCollector) Describe(output chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.state, collector.height, collector.generation, collector.interval, collector.observationTime, collector.successTime, collector.rpcRetrying} {
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
}
