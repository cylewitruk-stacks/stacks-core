#!/usr/bin/env node

import {createHash, randomBytes} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {loadInventory} from '../instrumentation/capability-manifest.mjs';
import {sha256File, sha256Value} from '../instrumentation/artifact-digest.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DNS_LABEL = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
const ACTOR_METRICS_JOBS = Object.freeze({
  node: 'stacks-node-metrics',
  signer: 'stacks-signer-metrics',
});
const ACTOR_METRICS_JOB_PATTERN = Object.values(ACTOR_METRICS_JOBS).join('|');

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

const FAMILY_PROVENANCE = new Set(['merged', 'attacknet-patch', 'unavailable']);

/** Convert one Ready v1beta1 StacksNetwork into the renderer's bounded input. */
export function manifestFromStacksNetwork(resource) {
  if (resource?.apiVersion !== 'testing.stacks.org/v1beta1' || resource.kind !== 'StacksNetwork') {
    throw new Error('observability source must be a v1beta1 StacksNetwork');
  }
  const {metadata = {}, status = {}} = resource;
  if (!metadata.name || !metadata.namespace || status.phase !== 'Ready'
    || status.inventoryReady !== true || status.observedGeneration !== metadata.generation
    || !/^sha256:[0-9a-f]{64}$/.test(status.inventoryDigest ?? '')
    || !Array.isArray(status.actors) || status.actors.length === 0) {
    throw new Error('StacksNetwork lacks a current complete admitted inventory');
  }
  const names = new Set();
  const workloads = status.actors.map(actor => {
    if (!actor?.name || names.has(actor.name) || !actor.role || !actor.identityReady
      || !DNS_LABEL.test(actor.serviceName ?? '') || actor.serviceName.length > 63
      || !actor.image || !/^sha256:[0-9a-f]{64}$/.test(actor.runtimeImageID ?? '')) {
      throw new Error('StacksNetwork contains an incomplete or duplicate admitted actor');
    }
    names.add(actor.name);
    return {
      service: actor.name,
      metricsService: actor.serviceName,
      role: actor.role,
      requestedImage: actor.image,
      instrumentation: {profile: 'unmodified', provenance: 'unavailable'},
    };
  });
  return {network: metadata.name, namespace: metadata.namespace, workloads};
}

function normalizedManifest(value) {
  return value?.kind === 'StacksNetwork' ? manifestFromStacksNetwork(value) : value;
}

export function instrumentationExpectationsFromPlan(plan, manifestPath) {
  if (plan?.schema !== 'stacks-attacknet-phase-1-qualification-plan/v1') {
    throw new Error('instrumentation plan uses an unsupported schema');
  }
  const unsigned = {...plan};
  delete unsigned.planDigest;
  if (plan.planDigest !== sha256Value(unsigned)) throw new Error('instrumentation plan digest mismatch');
  if (manifestPath !== undefined) {
    const supplied = resolve(manifestPath);
    if (resolve(plan.renderedManifest?.path ?? '') !== supplied
        || plan.renderedManifest?.digest !== sha256File(supplied)) {
      throw new Error('instrumentation plan does not bind the rendered manifest');
    }
  }
  if (!Array.isArray(plan.instrumentationFamilyExpectations)) {
    throw new Error('instrumentation plan omits per-family expectations');
  }
  return plan.instrumentationFamilyExpectations;
}

function expectationMap(manifest, expectations = []) {
  if (!Array.isArray(expectations)) throw new Error('instrumentation expectations must be an array');
  const actors = new Map((manifest.workloads ?? manifest.actors ?? []).map(actor => [actor.service, actor]));
  const inventory = loadInventory();
  const families = new Map(inventory.families.map(family => [family.id, family]));
  const result = new Map();
  for (const expectation of expectations) {
    const actor = actors.get(expectation?.actor);
    if (!actor) throw new Error(`instrumentation expectation references unknown actor ${expectation?.actor}`);
    if (expectation.role !== actor.role) throw new Error(`instrumentation expectation role mismatch for ${expectation.actor}`);
    if (result.has(expectation.actor)) throw new Error(`duplicate instrumentation expectation for ${expectation.actor}`);
    if (!Array.isArray(expectation.families)) throw new Error(`instrumentation expectation families are missing for ${expectation.actor}`);
    const actorFamilies = new Map();
    for (const declared of expectation.families) {
      const family = families.get(declared?.id);
      if (!family || !family.roles.includes(actor.role)) throw new Error(`invalid instrumentation family ${declared?.id} for ${expectation.actor}`);
      if (!FAMILY_PROVENANCE.has(declared.provenance)) throw new Error(`invalid ${declared.id} provenance for ${expectation.actor}`);
      if (actorFamilies.has(declared.id)) throw new Error(`duplicate instrumentation family ${declared.id} for ${expectation.actor}`);
      actorFamilies.set(declared.id, declared.provenance);
    }
    result.set(expectation.actor, actorFamilies);
  }
  for (const actor of actors.values()) {
    if ((actor.instrumentation?.provenance ?? 'unavailable') !== 'unavailable' && !result.has(actor.service)) {
      throw new Error(`available instrumentation declaration for ${actor.service} lacks per-family expectations`);
    }
  }
  return result;
}

function instrumentationProvenance(manifest, expectations = []) {
  const actors = manifest.workloads ?? manifest.actors ?? [];
  const expected = expectationMap(manifest, expectations);
  const inventory = loadInventory();
  return {
    schema: 'stacks-attacknet-instrumentation-provenance/v1',
    actors: actors.filter(actor => ['miner', 'companion', 'follower', 'signer'].includes(actor.role)).map(actor => {
      const actorExpected = expected.get(actor.service) ?? new Map();
      const fallback = (actor.instrumentation?.provenance ?? 'unavailable') === 'unavailable'
        ? 'unavailable' : undefined;
      return {
        actor: actor.service,
        role: actor.role,
        families: inventory.families.filter(family => family.roles.includes(actor.role)).map(family => {
          const provenance = actorExpected.get(family.id) ?? fallback;
          if (!provenance) throw new Error(`instrumentation expectation omits ${family.id} for ${actor.service}`);
          return {family: family.id, provenance};
        }),
      };
    }),
  };
}

function actorTargets(manifest) {
  const actors = manifest.workloads ?? manifest.actors ?? [];
  const nodes = actors.filter(actor => ['miner', 'companion', 'follower'].includes(actor.role));
  const signers = actors.filter(actor => actor.role === 'signer');
  const target = (actor, port) => {
    return {targets: [`${actor.metricsService ?? stableName(manifest.network, actor.service)}:${port}`], labels: {
      attacknet_network: manifest.network,
      attacknet_actor: actor.service,
      attacknet_role: actor.role,
      requested_image: actor.requestedImage ?? 'unknown',
      instrumentation_profile: actor.instrumentation?.profile ?? 'unmodified',
      instrumentation_provenance: actor.instrumentation?.provenance ?? 'unavailable',
      event_dispatch_mode: actor.eventDispatchMode ?? 'not-applicable',
      evidence_source: 'actor_self_reported',
    }};
  };
  return {
    nodes: nodes.map(actor => target(actor, 20446)),
    signers: signers.map(actor => target(actor, 31000)),
  };
}

function prometheusConfig(manifest, runOperatorTarget) {
  const bridge = `${stableName(manifest.network, 'attacknet-events')}:9464`;
  return `global:
  scrape_interval: 5s
  evaluation_interval: 5s
  external_labels:
    attacknet_network: ${manifest.network}
    evidence_scope: hacknet
rule_files:
  - /etc/prometheus/attacknet.rules.yml
scrape_configs:
  - job_name: ${ACTOR_METRICS_JOBS.node}
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
  - job_name: ${ACTOR_METRICS_JOBS.signer}
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
  - job_name: attacknet-run-controller
    honor_labels: false
    scrape_timeout: 3s
    sample_limit: 10000
    static_configs:
      - targets: ["${runOperatorTarget}"]
        labels:
          attacknet_network: ${manifest.network}
          evidence_source: orchestrator_observed
`;
}

export function validatePrometheusRulesAgainstInventory(rules, inventory = loadInventory()) {
  const families = new Map(inventory.families.map(item => [item.family, item]));
  const tokens = [...rules.matchAll(/\b(stacks_(?:node|signer)_[a-z0-9_]+?)(?:_total|_bucket|_sum|_count)?\b/g)];
  for (const match of tokens) {
    const family = families.get(match[1]);
    if (!family) throw new Error(`Prometheus rule references instrumentation family absent from inventory: ${match[1]}`);
    const exactName = match[0];
    const exactNameAllowed = family.exportedSample
      ? exactName === family.exportedSample
      : family.type === 'histogram'
        ? new RegExp(`^${family.family}_(?:bucket|sum|count)$`).test(exactName)
        : exactName === family.family;
    if (!exactNameAllowed) {
      throw new Error(`Prometheus rule references ${family.id} as ${exactName}, not its exact exporter name`);
    }
    const selector = rules.slice(match.index + match[0].length).match(/^\{([^}]*)\}/)?.[1] ?? '';
    for (const label of selector.matchAll(/([a-z_]+)(?:=|=~)"([^"]+)"/g)) {
      const domain = family.labels?.[label[1]];
      if (!domain) throw new Error(`Prometheus rule references unknown ${family.id} label ${label[1]}`);
      for (const value of label[2].split('|')) if (!domain.includes(value)) throw new Error(`Prometheus rule references unknown ${family.id}.${label[1]} value ${value}`);
    }
  }
  return true;
}

export function prometheusRules() {
  const absentRules = loadInventory().families.map(family => {
    // The Rust Prometheus exporters expose counters under the inventory's
    // declared family name (without an OpenMetrics `_total` suffix).
    // Histograms still need one concrete child series for presence detection.
    const sample = family.exportedSample ?? (family.type === 'histogram'
      ? `${family.family}_count` : family.family);
    const roles = family.roles.join('|');
    return `      - alert: AttacknetInstrumentationAbsent${family.id}
        expr: ((count by (attacknet_network, attacknet_actor) (attacknet_instrumentation_family_provenance{family="${family.id}",provenance=~"merged|attacknet-patch",attacknet_role=~"${roles}",evidence_source="orchestrator_observed"} == 1) and on (attacknet_network, attacknet_actor) count by (attacknet_network, attacknet_actor) (up{attacknet_role=~"${roles}"} == 1)) unless on (attacknet_network, attacknet_actor) count by (attacknet_network, attacknet_actor) (${sample})) > 0
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: Declared instrumentation family ${family.id} disappeared from a reachable actor`;
  }).join('\n');
  const rules = `groups:
  - name: attacknet-instrumentation
    rules:
      - alert: AttacknetInstrumentationProvenanceExporterAbsent
        expr: absent(attacknet_instrumentation_family_provenance) and on() (count(up{job=~"${ACTOR_METRICS_JOB_PATTERN}"}) > 0)
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: Instrumentation provenance inventory is absent for a non-empty actor topology
      - alert: AttacknetActorMetricsUnreachable
        expr: up{job=~"${ACTOR_METRICS_JOB_PATTERN}"} == 0
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: An enrolled actor metrics endpoint is unreachable
      - alert: AttacknetOrchestratorMetricsCollectionFailed
        expr: attacknet_orchestrator_metrics_collection_success == 0 or (absent(attacknet_orchestrator_metrics_collection_success) and on() (count(up{job="attacknet-run-controller"} == 1) > 0))
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: The run operator cannot publish authoritative campaign and run state
      - alert: AttacknetProtocolAssertionTerminalFailure
        expr: attacknet_run_protocol_assertion{outcome=~"Violated|Inconclusive"} == 1
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: An identity-bound AttacknetRun protocol assertion terminated unsuccessfully
      - alert: AttacknetCorrelatedSignerParticipationLoss
        expr: count(stacks_signer_registered_for_current_reward_cycle == 0) by (attacknet_network) >= 2
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: Multiple signer processes report no current-cycle registration
      - alert: AttacknetSignerStateFrozen
        expr: (time() - stacks_signer_state_last_changed_timestamp_seconds > 120) and on (attacknet_network, attacknet_actor) (stacks_signer_registered_for_current_reward_cycle == 1)
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: Registered signer state has not changed for two minutes
      - alert: AttacknetSignerValidationUnavailable
        expr: sum by (attacknet_network) (rate(stacks_signer_policy_evaluations{classification="unavailable"}[2m])) > 0
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: Signers are unable to evaluate proposals
      - alert: AttacknetNakamotoPropagationFailure
        expr: sum by (attacknet_network) (rate(stacks_node_nakamoto_block_transfers{outcome=~"failed|error|rejected"}[2m])) > 0
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: Nakamoto transport boundaries report propagation failures
${absentRules}
`;
  validatePrometheusRulesAgainstInventory(rules);
  return rules;
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

function lokiIngressPolicy(name, namespace, lokiLabels, alloyWriterLabels, grafanaLabels) {
  return {
    apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy',
    metadata: {name, namespace, labels: lokiLabels},
    spec: {
      podSelector: {matchLabels: lokiLabels},
      policyTypes: ['Ingress'],
      ingress: [{
        from: [
          {podSelector: {matchLabels: alloyWriterLabels}},
          {podSelector: {matchLabels: grafanaLabels}},
        ],
        ports: [{protocol: 'TCP', port: 3100}],
      }],
    },
  };
}

export function renderObservability(manifest, {
  eventToken,
  prometheusImage = 'prom/prometheus:v3.5.0',
  grafanaImage = 'grafana/grafana:12.1.0',
  pythonImage = 'python:3.13-alpine',
  lokiImage = 'grafana/loki:3.5.3',
  alloyImage = 'grafana/alloy:v1.10.0',
  runOperatorTarget = 'hacknet-run:8080',
  instrumentationExpectations = [],
} = {}) {
  manifest = normalizedManifest(manifest);
  const network = manifest.network;
  const namespace = manifest.namespace;
  if (!DNS_LABEL.test(network) || network.length > 63 || !DNS_LABEL.test(namespace) || namespace.length > 63) throw new Error('manifest network and namespace must be DNS labels of at most 63 characters');
  if (!/^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?:[1-9][0-9]{0,4}$/.test(runOperatorTarget)) {
    throw new Error('runOperatorTarget must be a bounded DNS name and TCP port');
  }
  const token = eventToken ?? randomBytes(32).toString('hex');
  if (token.length < 32) throw new Error('eventToken must contain at least 32 characters');
  const provenanceData = instrumentationProvenance(manifest, instrumentationExpectations);
  const provenanceConfig = `${JSON.stringify(provenanceData, null, 2)}\n`;
  const targetData = actorTargets(manifest);
  const overview = readFileSync(join(ROOT, 'dashboards', 'attacknet-overview.json'), 'utf8');
  const actorDashboard = readFileSync(join(ROOT, 'dashboards', 'attacknet-actor.json'), 'utf8');
  const eventSource = readFileSync(join(ROOT, 'event_bridge.py'), 'utf8');
  const promConfig = prometheusConfig(manifest, runOperatorTarget);
  const promRules = prometheusRules();
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
  const alloyWriterLabels = {
    'testing.stacks.org/network': network,
    'testing.stacks.org/loki-writer': 'true',
  };
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
    configMap(names.events, namespace, eventLabels, {
      'event_bridge.py': eventSource,
      'instrumentation-provenance.json': provenanceConfig,
    }),
    {apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: {name: names.events, namespace, labels: eventLabels}, spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage: '1Gi'}}}},
    {
      apiVersion: 'apps/v1', kind: 'Deployment', metadata: {name: names.events, namespace, labels: eventLabels},
      spec: {replicas: 1, selector: {matchLabels: eventLabels}, strategy: {type: 'Recreate'}, template: {metadata: {labels: eventLabels, annotations: {'testing.stacks.org/config-sha256': digest(eventSource, provenanceConfig)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(65532),
        containers: [{name: 'events', image: pythonImage, imagePullPolicy: 'IfNotPresent', command: ['python3', '/opt/attacknet/event_bridge.py', '--instrumentation-provenance=/opt/attacknet/instrumentation-provenance.json'], ports: [{name: 'http', containerPort: 9464}], securityContext: containerSecurity(), resources: {requests: {cpu: '20m', memory: '32Mi'}, limits: {cpu: '500m', memory: '256Mi'}}, readinessProbe: {httpGet: {path: '/healthz', port: 'http'}, periodSeconds: 3}, volumeMounts: [{name: 'source', mountPath: '/opt/attacknet/event_bridge.py', subPath: 'event_bridge.py', readOnly: true}, {name: 'source', mountPath: '/opt/attacknet/instrumentation-provenance.json', subPath: 'instrumentation-provenance.json', readOnly: true}, {name: 'token', mountPath: '/run/secrets/attacknet', readOnly: true}, {name: 'data', mountPath: '/data'}, {name: 'tmp', mountPath: '/tmp'}]}],
        volumes: [{name: 'source', configMap: {name: names.events, defaultMode: 365}}, {name: 'token', secret: {secretName: names.eventWriter}}, {name: 'data', persistentVolumeClaim: {claimName: names.events}}, {name: 'tmp', emptyDir: {}}],
      }}}},
    service(names.events, namespace, eventLabels, [{name: 'http', port: 9464, targetPort: 'http'}]),
    configMap(names.prometheus, namespace, promLabels, {
      'prometheus.yml': promConfig,
      'attacknet.rules.yml': promRules,
      'nodes.json': nodeTargets,
      'signers.json': signerTargets,
    }),
    {apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: {name: names.prometheus, namespace, labels: promLabels}, spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage: '2Gi'}}}},
    {
      apiVersion: 'apps/v1', kind: 'Deployment', metadata: {name: names.prometheus, namespace, labels: promLabels},
      spec: {replicas: 1, selector: {matchLabels: promLabels}, strategy: {type: 'Recreate'}, template: {metadata: {labels: promLabels, annotations: {'testing.stacks.org/config-sha256': digest(promConfig, promRules, nodeTargets, signerTargets)}}, spec: {
        automountServiceAccountToken: false, securityContext: podSecurity(65534),
        containers: [{name: 'prometheus', image: prometheusImage, imagePullPolicy: 'IfNotPresent', args: ['--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.path=/prometheus', '--storage.tsdb.retention.time=7d', '--web.enable-lifecycle'], ports: [{name: 'http', containerPort: 9090}], securityContext: containerSecurity(), resources: {requests: {cpu: '100m', memory: '256Mi'}, limits: {cpu: '2', memory: '2Gi'}}, readinessProbe: {httpGet: {path: '/-/ready', port: 'http'}, periodSeconds: 5}, volumeMounts: [{name: 'config', mountPath: '/etc/prometheus/prometheus.yml', subPath: 'prometheus.yml', readOnly: true}, {name: 'config', mountPath: '/etc/prometheus/attacknet.rules.yml', subPath: 'attacknet.rules.yml', readOnly: true}, {name: 'config', mountPath: '/etc/prometheus/targets/nodes.json', subPath: 'nodes.json', readOnly: true}, {name: 'config', mountPath: '/etc/prometheus/targets/signers.json', subPath: 'signers.json', readOnly: true}, {name: 'data', mountPath: '/prometheus'}, {name: 'tmp', mountPath: '/tmp'}]}],
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
    lokiIngressPolicy(
      stableName(network, 'attacknet-loki-ingress'), namespace,
      lokiLabels, alloyWriterLabels, grafanaLabels,
    ),
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
      spec: {selector: {matchLabels: alloyLabels}, updateStrategy: {type: 'RollingUpdate', rollingUpdate: {maxUnavailable: 1}}, template: {metadata: {labels: {...alloyLabels, ...alloyWriterLabels}, annotations: {'testing.stacks.org/config-sha256': digest(collectorConfig)}}, spec: {
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
  if (!manifestPath) throw new Error('usage: render.mjs MANIFEST_OR_STACKSNETWORK [--output=FILE] [--event-token=TOKEN]');
  const output = resolve(option('output', join(ROOT, 'generated', 'observability.json')));
  const tokenOutput = resolve(option('token-output', join(dirname(output), 'event-token')));
  const instrumentationPlanPath = option('instrumentation-plan', undefined);
  const instrumentationExpectations = instrumentationPlanPath
    ? instrumentationExpectationsFromPlan(
      JSON.parse(readFileSync(resolve(instrumentationPlanPath), 'utf8')),
      manifestPath,
    )
    : [];
  const resource = renderObservability(JSON.parse(readFileSync(manifestPath, 'utf8')), {
    eventToken: option('event-token', undefined),
    prometheusImage: option('prometheus-image', 'prom/prometheus:v3.5.0'),
    grafanaImage: option('grafana-image', 'grafana/grafana:12.1.0'),
    pythonImage: option('python-image', 'python:3.13-alpine'),
    lokiImage: option('loki-image', 'grafana/loki:3.5.3'),
    alloyImage: option('alloy-image', 'grafana/alloy:v1.10.0'),
    runOperatorTarget: option('run-operator-target', 'hacknet-run:8080'),
    instrumentationExpectations,
  });
  mkdirSync(dirname(output), {recursive: true});
  writeFileSync(output, `${JSON.stringify(resource, null, 2)}\n`, {mode: 0o600});
  const token = resource.items.find(item => item.kind === 'Secret').stringData.token;
  writeFileSync(tokenOutput, `${token}\n`, {mode: 0o600});
  console.log(`Rendered attacknet observability resources to ${output}`);
}
