#!/usr/bin/env node

import {createHash, randomBytes} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DNS_LABEL = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;

function option(name, fallback) {
  const marker = `--${name}=`;
  return process.argv.find(value => value.startsWith(marker))?.slice(marker.length) ?? fallback;
}

function labels(network, component) {
  return {'app.kubernetes.io/name': `attacknet-${component}`, 'app.kubernetes.io/part-of': 'stacks-attacknet', 'testing.stacks.org/network': network};
}

// Keep target names identical to the hacknet operator's stable_name(). This is
// load-bearing for long experiment/actor names: the manifest stores logical
// names while Kubernetes sees the bounded child-resource name.
function stableName(network, actor) {
  const candidate = `${network}-${actor}`;
  if (candidate.length <= 63) return candidate;
  const digest = createHash('sha256').update(candidate).digest('hex').slice(0, 8);
  return `${candidate.slice(0, 54).replace(/-+$/, '')}-${digest}`;
}

function digest(...values) {
  return createHash('sha256').update(values.join('\0')).digest('hex');
}

function podSecurity(uid) {
  return {runAsNonRoot: true, runAsUser: uid, runAsGroup: uid, fsGroup: uid, seccompProfile: {type: 'RuntimeDefault'}};
}

function containerSecurity() {
  return {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ['ALL']}};
}

function actorTargets(manifest) {
  const actors = manifest.workloads ?? manifest.actors ?? [];
  const nodes = actors.filter(actor => ['miner', 'companion', 'follower'].includes(actor.role));
  const signers = actors.filter(actor => actor.role === 'signer');
  const target = (actor, port) => ({
    targets: [`${stableName(manifest.network, actor.service)}:${port}`],
    labels: {
      attacknet_network: manifest.network,
      attacknet_actor: actor.service,
      attacknet_role: actor.role,
      evidence_source: 'actor_self_reported',
    },
  });
  return {
    nodes: nodes.map(actor => target(actor, 20446)),
    signers: signers.map(actor => target(actor, 31000)),
  };
}

function prometheusConfig(manifest) {
  const bridge = `${stableName(manifest.network, 'attacknet-events')}:9464`;
  return `global:
  scrape_interval: 5s
  evaluation_interval: 5s
  external_labels:
    attacknet_network: ${manifest.network}
    evidence_scope: hacknet
scrape_configs:
  - job_name: stacks-node-metrics
    honor_labels: false
    honor_timestamps: false
    scrape_timeout: 3s
    sample_limit: 50000
    label_limit: 64
    label_name_length_limit: 128
    label_value_length_limit: 1024
    body_size_limit: 16MB
    file_sd_configs:
      - files: [/etc/prometheus/targets/nodes.json]
        refresh_interval: 30s
  - job_name: stacks-signer-metrics
    honor_labels: false
    honor_timestamps: false
    scrape_timeout: 3s
    sample_limit: 50000
    label_limit: 64
    label_name_length_limit: 128
    label_value_length_limit: 1024
    body_size_limit: 16MB
    file_sd_configs:
      - files: [/etc/prometheus/targets/signers.json]
        refresh_interval: 30s
  - job_name: attacknet-orchestrator-events
    honor_labels: false
    scrape_timeout: 3s
    sample_limit: 10000
    static_configs:
      - targets: ["${bridge}"]
        labels:
          attacknet_network: ${manifest.network}
          evidence_source: orchestrator_observed
`;
}

function lokiConfig() {
  return `auth_enabled: false
server:
  http_listen_port: 3100
  grpc_listen_port: 9096
common:
  path_prefix: /loki
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
schema_config:
  configs:
    - from: "2024-01-01"
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
storage_config:
  tsdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/index-cache
compactor:
  working_directory: /loki/compactor
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 20
  delete_request_store: filesystem
limits_config:
  retention_period: 168h
  max_query_lookback: 168h
  max_query_length: 168h
  ingestion_rate_mb: 8
  ingestion_burst_size_mb: 16
  max_line_size: 256KB
  max_line_size_truncate: true
  max_entries_limit_per_query: 10000
analytics:
  reporting_enabled: false
`;
}

function alloyConfig(manifest) {
  const loki = `${stableName(manifest.network, 'attacknet-loki')}:3100`;
  // Log bodies are never parsed for labels. Every indexed identity/trust label
  // below comes from Kubernetes discovery or this trusted collector config.
  // In particular, an adversarial actor cannot forge another actor's stream by
  // printing JSON or logfmt fields that happen to resemble these labels.
  return `logging {
  level = "info"
}

discovery.kubernetes "actor_pods" {
  role = "pod"
  namespaces {
    names = ["${manifest.namespace}"]
  }
  selectors {
    role  = "pod"
    field = "spec.nodeName=" + sys.env("NODE_NAME")
    label = "app.kubernetes.io/name=stacks-hacknet-actor,testing.stacks.org/network=${manifest.network}"
  }
}

discovery.relabel "actor_logs" {
  targets = discovery.kubernetes.actor_pods.targets

  rule {
    source_labels = ["__meta_kubernetes_pod_container_init"]
    regex         = "true"
    action        = "drop"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_label_testing_stacks_org_network"]
    target_label  = "attacknet_network"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_label_testing_stacks_org_actor"]
    target_label  = "attacknet_actor"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_label_testing_stacks_org_role"]
    target_label  = "attacknet_role"
  }
  rule {
    source_labels = ["__meta_kubernetes_namespace"]
    target_label  = "k8s_namespace"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_name"]
    target_label  = "k8s_pod"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_uid"]
    target_label  = "k8s_pod_uid"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_node_name"]
    target_label  = "k8s_node"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_container_name"]
    target_label  = "k8s_container"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_container_image"]
    target_label  = "requested_image"
  }
  rule {
    source_labels = ["__meta_kubernetes_pod_container_id"]
    regex         = "[^:]+://(.+)"
    replacement   = "$1"
    target_label  = "resolved_container_id"
  }
  rule {
    replacement  = "actor_self_reported_untrusted"
    target_label = "log_content_trust"
  }
  rule {
    replacement  = "kubernetes_collector_attached"
    target_label = "metadata_trust"
  }
}

loki.source.kubernetes "actor_logs" {
  targets    = discovery.relabel.actor_logs.output
  forward_to = [loki.write.attacknet.receiver]
}

loki.write "attacknet" {
  endpoint {
    url = "http://${loki}/loki/api/v1/push"
  }
}
`;
}

function grafanaDatasource(network) {
  return `apiVersion: 1
datasources:
  - name: Attacknet Prometheus
    uid: attacknet-prometheus
    type: prometheus
    access: proxy
    url: http://${stableName(network, 'attacknet-prometheus')}:9090
    isDefault: true
    editable: false
  - name: Attacknet Loki
    uid: attacknet-loki
    type: loki
    access: proxy
    url: http://${stableName(network, 'attacknet-loki')}:3100
    isDefault: false
    editable: false
`;
}

const grafanaDashboards = `apiVersion: 1
providers:
  - name: Stacks Attacknet
    orgId: 1
    folder: Stacks Attacknet
    type: file
    disableDeletion: true
    editable: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
`;

function configMap(name, namespace, metadataLabels, data) {
  return {apiVersion: 'v1', kind: 'ConfigMap', metadata: {name, namespace, labels: metadataLabels}, data};
}

function service(name, namespace, metadataLabels, ports) {
  return {apiVersion: 'v1', kind: 'Service', metadata: {name, namespace, labels: metadataLabels}, spec: {selector: metadataLabels, ports}};
}

export function renderObservability(manifest, {
  eventToken,
  prometheusImage = 'prom/prometheus:v3.5.0',
  grafanaImage = 'grafana/grafana:12.1.0',
  pythonImage = 'python:3.13-alpine',
  lokiImage = 'grafana/loki:3.5.3',
  alloyImage = 'grafana/alloy:v1.10.0',
} = {}) {
  const network = manifest.network;
  const namespace = manifest.namespace;
  if (!DNS_LABEL.test(network) || network.length > 63 || !DNS_LABEL.test(namespace) || namespace.length > 63) throw new Error('manifest network and namespace must be DNS labels of at most 63 characters');
  const token = eventToken ?? randomBytes(32).toString('hex');
  if (token.length < 32) throw new Error('eventToken must contain at least 32 characters');
  const targetData = actorTargets(manifest);
  const overview = readFileSync(join(ROOT, 'dashboards', 'attacknet-overview.json'), 'utf8');
  const actorDashboard = readFileSync(join(ROOT, 'dashboards', 'attacknet-actor.json'), 'utf8');
  const eventSource = readFileSync(join(ROOT, 'event_bridge.py'), 'utf8');
  const promConfig = prometheusConfig(manifest);
  const logsConfig = lokiConfig();
  const collectorConfig = alloyConfig(manifest);
  const nodeTargets = `${JSON.stringify(targetData.nodes, null, 2)}\n`;
  const signerTargets = `${JSON.stringify(targetData.signers, null, 2)}\n`;
  const datasource = grafanaDatasource(network);
  const promLabels = labels(network, 'prometheus');
  const grafanaLabels = labels(network, 'grafana');
  const eventLabels = labels(network, 'events');
  const lokiLabels = labels(network, 'loki');
  const alloyLabels = labels(network, 'alloy');
  const names = {
    eventWriter: stableName(network, 'attacknet-event-writer'),
    events: stableName(network, 'attacknet-events'),
    prometheus: stableName(network, 'attacknet-prometheus'),
    grafana: stableName(network, 'attacknet-grafana'),
    loki: stableName(network, 'attacknet-loki'),
    alloy: stableName(network, 'attacknet-alloy'),
  };
  const resources = [
    {apiVersion: 'v1', kind: 'Secret', metadata: {name: names.eventWriter, namespace, labels: eventLabels}, type: 'Opaque', stringData: {token}},
    configMap(names.events, namespace, eventLabels, {'event_bridge.py': eventSource}),
    {apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: {name: names.events, namespace, labels: eventLabels}, spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage: '1Gi'}}}},
    {
      apiVersion: 'apps/v1', kind: 'Deployment', metadata: {name: names.events, namespace, labels: eventLabels},
      spec: {replicas: 1, selector: {matchLabels: eventLabels}, strategy: {type: 'Recreate'}, template: {metadata: {labels: eventLabels, annotations: {'testing.stacks.org/config-sha256': digest(eventSource)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(65532),
        containers: [{name: 'events', image: pythonImage, imagePullPolicy: 'IfNotPresent', command: ['python3', '/opt/attacknet/event_bridge.py'], ports: [{name: 'http', containerPort: 9464}], securityContext: containerSecurity(), resources: {requests: {cpu: '20m', memory: '32Mi'}, limits: {cpu: '500m', memory: '256Mi'}}, readinessProbe: {httpGet: {path: '/healthz', port: 'http'}, periodSeconds: 3}, volumeMounts: [{name: 'source', mountPath: '/opt/attacknet/event_bridge.py', subPath: 'event_bridge.py', readOnly: true}, {name: 'token', mountPath: '/run/secrets/attacknet', readOnly: true}, {name: 'data', mountPath: '/data'}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'source', configMap: {name: names.events, defaultMode: 365}}, {name: 'token', secret: {secretName: names.eventWriter}}, {name: 'data', persistentVolumeClaim: {claimName: names.events}}, {name: 'tmp', emptyDir: {}}],
      }}}},
    service(names.events, namespace, eventLabels, [{name: 'http', port: 9464, targetPort: 'http'}]),
    configMap(names.prometheus, namespace, promLabels, {
      'prometheus.yml': promConfig,
      'nodes.json': nodeTargets,
      'signers.json': signerTargets,
    }),
    {apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: {name: names.prometheus, namespace, labels: promLabels}, spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage: '2Gi'}}}},
    {
      apiVersion: 'apps/v1', kind: 'Deployment', metadata: {name: names.prometheus, namespace, labels: promLabels},
      spec: {replicas: 1, selector: {matchLabels: promLabels}, strategy: {type: 'Recreate'}, template: {metadata: {labels: promLabels, annotations: {'testing.stacks.org/config-sha256': digest(promConfig, nodeTargets, signerTargets)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(65534),
        containers: [{name: 'prometheus', image: prometheusImage, imagePullPolicy: 'IfNotPresent', args: ['--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.path=/prometheus', '--storage.tsdb.retention.time=7d', '--web.enable-lifecycle'], ports: [{name: 'http', containerPort: 9090}], securityContext: containerSecurity(), resources: {requests: {cpu: '100m', memory: '256Mi'}, limits: {cpu: '2', memory: '2Gi'}}, readinessProbe: {httpGet: {path: '/-/ready', port: 'http'}, periodSeconds: 5}, volumeMounts: [{name: 'config', mountPath: '/etc/prometheus/prometheus.yml', subPath: 'prometheus.yml', readOnly: true}, {name: 'config', mountPath: '/etc/prometheus/targets/nodes.json', subPath: 'nodes.json', readOnly: true}, {name: 'config', mountPath: '/etc/prometheus/targets/signers.json', subPath: 'signers.json', readOnly: true}, {name: 'data', mountPath: '/prometheus'}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'config', configMap: {name: names.prometheus}}, {name: 'data', persistentVolumeClaim: {claimName: names.prometheus}}, {name: 'tmp', emptyDir: {}}],
      }}}},
    service(names.prometheus, namespace, promLabels, [{name: 'http', port: 9090, targetPort: 'http'}]),
    configMap(names.loki, namespace, lokiLabels, {'loki.yaml': logsConfig}),
    {apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: {name: names.loki, namespace, labels: lokiLabels}, spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage: '5Gi'}}}},
    {
      apiVersion: 'apps/v1', kind: 'StatefulSet', metadata: {name: names.loki, namespace, labels: lokiLabels},
      spec: {replicas: 1, serviceName: names.loki, selector: {matchLabels: lokiLabels}, updateStrategy: {type: 'RollingUpdate'}, template: {metadata: {labels: lokiLabels, annotations: {'testing.stacks.org/config-sha256': digest(logsConfig)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(10001),
        containers: [{name: 'loki', image: lokiImage, imagePullPolicy: 'IfNotPresent', args: ['-config.file=/etc/loki/loki.yaml'], ports: [{name: 'http', containerPort: 3100}, {name: 'grpc', containerPort: 9096}], securityContext: containerSecurity(), resources: {requests: {cpu: '100m', memory: '256Mi', 'ephemeral-storage': '64Mi'}, limits: {cpu: '2', memory: '2Gi', 'ephemeral-storage': '256Mi'}}, readinessProbe: {httpGet: {path: '/ready', port: 'http'}, periodSeconds: 5}, volumeMounts: [{name: 'config', mountPath: '/etc/loki/loki.yaml', subPath: 'loki.yaml', readOnly: true}, {name: 'data', mountPath: '/loki'}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'config', configMap: {name: names.loki}}, {name: 'data', persistentVolumeClaim: {claimName: names.loki}}, {name: 'tmp', emptyDir: {sizeLimit: '128Mi'}}],
      }}}},
    service(names.loki, namespace, lokiLabels, [{name: 'http', port: 3100, targetPort: 'http'}]),
    {apiVersion: 'v1', kind: 'ServiceAccount', metadata: {name: names.alloy, namespace, labels: alloyLabels}, automountServiceAccountToken: false},
    {
      apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: {name: names.alloy, namespace, labels: alloyLabels},
      rules: [
        {apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'watch']},
        {apiGroups: [''], resources: ['pods/log'], verbs: ['get']},
      ],
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: {name: names.alloy, namespace, labels: alloyLabels},
      subjects: [{kind: 'ServiceAccount', name: names.alloy, namespace}],
      roleRef: {apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: names.alloy},
    },
    configMap(names.alloy, namespace, alloyLabels, {'config.alloy': collectorConfig}),
    {
      apiVersion: 'apps/v1', kind: 'DaemonSet', metadata: {name: names.alloy, namespace, labels: alloyLabels},
      spec: {selector: {matchLabels: alloyLabels}, updateStrategy: {type: 'RollingUpdate', rollingUpdate: {maxUnavailable: 1}}, template: {metadata: {labels: alloyLabels, annotations: {'testing.stacks.org/config-sha256': digest(collectorConfig)}}, spec: {
        serviceAccountName: names.alloy, automountServiceAccountToken: false, securityContext: podSecurity(473), tolerations: [
          {key: 'node-role.kubernetes.io/control-plane', operator: 'Exists', effect: 'NoSchedule'},
          {key: 'node-role.kubernetes.io/master', operator: 'Exists', effect: 'NoSchedule'},
        ],
        containers: [{name: 'alloy', image: alloyImage, imagePullPolicy: 'IfNotPresent', args: ['run', '--server.http.listen-addr=0.0.0.0:12345', '--storage.path=/var/lib/alloy/data', '/etc/alloy/config.alloy'], env: [{name: 'NODE_NAME', valueFrom: {fieldRef: {fieldPath: 'spec.nodeName'}}}], ports: [{name: 'http', containerPort: 12345}], securityContext: containerSecurity(), resources: {requests: {cpu: '50m', memory: '96Mi', 'ephemeral-storage': '32Mi'}, limits: {cpu: '1', memory: '512Mi', 'ephemeral-storage': '256Mi'}}, readinessProbe: {httpGet: {path: '/-/ready', port: 'http'}, periodSeconds: 5}, volumeMounts: [{name: 'config', mountPath: '/etc/alloy/config.alloy', subPath: 'config.alloy', readOnly: true}, {name: 'state', mountPath: '/var/lib/alloy/data'}, {name: 'service-account', mountPath: '/var/run/secrets/kubernetes.io/serviceaccount', readOnly: true}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'config', configMap: {name: names.alloy}}, {name: 'state', emptyDir: {sizeLimit: '128Mi'}}, {name: 'service-account', projected: {defaultMode: 420, sources: [{serviceAccountToken: {path: 'token', expirationSeconds: 3600}}, {configMap: {name: 'kube-root-ca.crt', items: [{key: 'ca.crt', path: 'ca.crt'}]}}, {downwardAPI: {items: [{path: 'namespace', fieldRef: {fieldPath: 'metadata.namespace'}}]}}]}}, {name: 'tmp', emptyDir: {sizeLimit: '64Mi'}}],
      }}}},
    configMap(names.grafana, namespace, grafanaLabels, {
      'datasource.yaml': datasource,
      'dashboards.yaml': grafanaDashboards,
      'attacknet-overview.json': overview,
      'attacknet-actor.json': actorDashboard,
    }),
    {
      apiVersion: 'apps/v1', kind: 'Deployment', metadata: {name: names.grafana, namespace, labels: grafanaLabels},
      spec: {replicas: 1, selector: {matchLabels: grafanaLabels}, template: {metadata: {labels: grafanaLabels, annotations: {'testing.stacks.org/config-sha256': digest(datasource, grafanaDashboards, overview, actorDashboard)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(472),
        containers: [{name: 'grafana', image: grafanaImage, imagePullPolicy: 'IfNotPresent', env: [{name: 'GF_AUTH_ANONYMOUS_ENABLED', value: 'true'}, {name: 'GF_AUTH_ANONYMOUS_ORG_ROLE', value: 'Viewer'}, {name: 'GF_AUTH_DISABLE_LOGIN_FORM', value: 'true'}, {name: 'GF_USERS_ALLOW_SIGN_UP', value: 'false'}, {name: 'GF_PATHS_DATA', value: '/var/lib/grafana/data'}], ports: [{name: 'http', containerPort: 3000}], securityContext: containerSecurity(), resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '1', memory: '1Gi'}}, readinessProbe: {httpGet: {path: '/api/health', port: 'http'}, periodSeconds: 5}, volumeMounts: [{name: 'config', mountPath: '/etc/grafana/provisioning/datasources/datasource.yaml', subPath: 'datasource.yaml', readOnly: true}, {name: 'config', mountPath: '/etc/grafana/provisioning/dashboards/dashboards.yaml', subPath: 'dashboards.yaml', readOnly: true}, {name: 'config', mountPath: '/var/lib/grafana/dashboards/attacknet-overview.json', subPath: 'attacknet-overview.json', readOnly: true}, {name: 'config', mountPath: '/var/lib/grafana/dashboards/attacknet-actor.json', subPath: 'attacknet-actor.json', readOnly: true}, {name: 'data', mountPath: '/var/lib/grafana/data'}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'config', configMap: {name: names.grafana}}, {name: 'data', emptyDir: {}}, {name: 'tmp', emptyDir: {}}],
      }}}},
    service(names.grafana, namespace, grafanaLabels, [{name: 'http', port: 3000, targetPort: 'http'}]),
  ];
  return {apiVersion: 'v1', kind: 'List', metadata: {annotations: {'testing.stacks.org/generated-for': network}}, items: resources};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const manifestPath = process.argv[2];
  if (!manifestPath) throw new Error('usage: render.mjs MANIFEST [--output=FILE] [--event-token=TOKEN]');
  const output = resolve(option('output', join(ROOT, 'generated', 'observability.json')));
  const tokenOutput = resolve(option('token-output', join(dirname(output), 'event-token')));
  const resource = renderObservability(JSON.parse(readFileSync(manifestPath, 'utf8')), {
    eventToken: option('event-token', undefined),
    prometheusImage: option('prometheus-image', 'prom/prometheus:v3.5.0'),
    grafanaImage: option('grafana-image', 'grafana/grafana:12.1.0'),
    pythonImage: option('python-image', 'python:3.13-alpine'),
    lokiImage: option('loki-image', 'grafana/loki:3.5.3'),
    alloyImage: option('alloy-image', 'grafana/alloy:v1.10.0'),
  });
  mkdirSync(dirname(output), {recursive: true});
  writeFileSync(output, `${JSON.stringify(resource, null, 2)}\n`, {mode: 0o600});
  const token = resource.items.find(item => item.kind === 'Secret').stringData.token;
  writeFileSync(tokenOutput, `${token}\n`, {mode: 0o600});
  console.log(`Rendered attacknet observability resources to ${output}`);
}
