package topology

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	attacknetv1alpha1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1alpha1"
)

func (c actorContext) configMap() (*corev1.ConfigMap, error) {
	telemetry := telemetrySettings(c.network, c.actor)
	data := map[string]string{}
	if c.actor.Config != nil {
		if c.actor.Config.Inline != "" {
			value, err := c.expand(c.actor.Config.Inline)
			if err != nil {
				return nil, err
			}
			data[configKey(c.actor)] = value
		}
		for key, source := range c.actor.Config.Files {
			value, err := c.expand(source)
			if err != nil {
				return nil, err
			}
			data[key] = value
		}
	}
	if boolValue(telemetry.Enabled, false) {
		data["otelcol.yaml"] = c.otelConfig(telemetry)
	}
	if len(data) == 0 {
		return nil, nil
	}
	result := &corev1.ConfigMap{ObjectMeta: c.metadata(), Data: data}
	if err := c.own(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c actorContext) service() (*corev1.Service, error) {
	ports := effectivePorts(c.actor)
	servicePorts := make([]corev1.ServicePort, 0, len(ports)+1)
	for _, port := range ports {
		servicePorts = append(servicePorts, corev1.ServicePort{Name: port.Name, Port: port.ServicePort, TargetPort: intstr.FromString(port.Name), Protocol: port.Protocol})
	}
	if boolValue(probeSettings(c.network, c.actor).Enabled, false) {
		servicePorts = append(servicePorts, corev1.ServicePort{Name: "probe", Port: 18080, TargetPort: intstr.FromString("probe"), Protocol: corev1.ProtocolTCP})
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	result := &corev1.Service{ObjectMeta: c.metadata(), Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone,
		PublishNotReadyAddresses: c.actor.RuntimeExposure == "reachable",
		Selector:                 map[string]string{networkLabel: c.network.Name, actorLabel: c.actor.Name}, Ports: servicePorts,
		SessionAffinity:       corev1.ServiceAffinityNone,
		InternalTrafficPolicy: &internalTrafficPolicy,
	}}
	if err := c.own(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c actorContext) otelConfig(telemetry attacknetv1alpha1.TelemetrySpec) string {
	metricsPort := telemetry.MetricsPort
	if metricsPort == 0 {
		if c.actor.Role == "signer" {
			metricsPort = 31000
		} else {
			metricsPort = 20446
		}
	}
	headers := ""
	if telemetry.TokenSecretRef != nil {
		headers = "    headers:\n      Authorization: \"Bearer ${env:STACKS_FEDERATION_TOKEN}\"\n"
	}
	serviceName := "stacks-node"
	if c.actor.Role == "signer" {
		serviceName = "stacks-signer"
	}
	return fmt.Sprintf(`extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: stacks-actor
          scrape_interval: 5s
          scrape_timeout: 2s
          static_configs:
            - targets: ["127.0.0.1:%d"]
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
    spike_limit_mib: 32
  resource/actor:
    attributes:
      - key: service.name
        action: upsert
        value: %s
      - key: stacks.actor.name
        action: upsert
        value: %s
      - key: stacks.actor.role
        action: upsert
        value: %s
  batch:
    timeout: 2s
exporters:
  otlp_http/federation:
    endpoint: "${env:STACKS_FEDERATION_ENDPOINT}"
%s    compression: gzip
    sending_queue:
      enabled: true
      queue_size: 500
    retry_on_failure:
      enabled: true
      max_elapsed_time: 60s
service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [prometheus]
      processors: [memory_limiter, resource/actor, batch]
      exporters: [otlp_http/federation]
`, metricsPort, serviceName, c.actor.Name, c.actor.Role, headers)
}
