import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {loadInventory} from '../instrumentation/capability-manifest.mjs';
import {sha256File, sha256Value} from '../instrumentation/artifact-digest.mjs';
import {instrumentationExpectationsFromPlan, manifestFromStacksNetwork, renderObservability} from './render.mjs';
import {readEvents, renderReport} from './report.mjs';

const manifest = {
  schemaVersion: 1,
  network: 'attacknet-test',
  namespace: 'hacknet-system',
  workloads: [
    {service: 'miner-1', type: 'node', role: 'miner', requestedImage: 'stacks:patched', instrumentation: {profile: 'patched-main', provenance: 'mixed'}, eventDispatchMode: 'queued'},
    {service: 'signer-node-1', type: 'node', role: 'companion'},
    {service: 'signer-1', type: 'signer', role: 'signer'},
    {service: 'follower-1', type: 'node', role: 'follower'},
    {service: 'bitcoin', type: 'infrastructure', role: 'burnchain'},
  ],
};

const instrumentationExpectations = [{
  actor: 'miner-1', role: 'miner',
  families: loadInventory().families.filter(family => family.roles.includes('miner')).map(family => ({
    id: family.id,
    provenance: family.id === 'M19' ? 'unavailable' : 'attacknet-patch',
  })),
}];

function render(options = {}) {
  return renderObservability(manifest, {
    eventToken: 'c'.repeat(64), instrumentationExpectations, ...options,
  });
}

function labelsFor(network, component) {
  return {
    'app.kubernetes.io/name': `attacknet-${component}`,
    'app.kubernetes.io/part-of': 'stacks-attacknet',
    'testing.stacks.org/network': network,
  };
}

function labelSort(left, right) {
  return JSON.stringify(left).localeCompare(JSON.stringify(right));
}

test('renderer consumes only a current complete admitted StacksNetwork inventory', () => {
  const network = {
    apiVersion: 'testing.stacks.org/v1beta1', kind: 'StacksNetwork',
    metadata: {name: 'live-network', namespace: 'hacknet-system', generation: 3},
    status: {
      phase: 'Ready', observedGeneration: 3, inventoryReady: true,
      inventoryDigest: `sha256:${'a'.repeat(64)}`,
      actors: [{
        name: 'follower-1', role: 'follower', image: 'stacks:current', serviceName: 'live-network-follower-1',
        identityReady: true, runtimeImageID: `sha256:${'b'.repeat(64)}`,
      }],
    },
  };
  const derived = manifestFromStacksNetwork(network);
  assert.deepEqual(derived.workloads, [{
    service: 'follower-1', metricsService: 'live-network-follower-1',
    role: 'follower', requestedImage: 'stacks:current',
    instrumentation: {profile: 'unmodified', provenance: 'unavailable'},
  }]);
  const rendered = renderObservability(network, {eventToken: 'c'.repeat(64)});
  const prometheus = rendered.items.find(item => item.kind === 'ConfigMap'
    && item.metadata.name === 'live-network-attacknet-prometheus');
  assert.deepEqual(JSON.parse(prometheus.data['nodes.json'])[0].targets, ['live-network-follower-1:20446']);
  network.status.actors[0].serviceName = 'authoritative-follower-service';
  const renamed = renderObservability(network, {eventToken: 'c'.repeat(64)});
  const renamedPrometheus = renamed.items.find(item => item.kind === 'ConfigMap'
    && item.metadata.name === 'live-network-attacknet-prometheus');
  assert.deepEqual(JSON.parse(renamedPrometheus.data['nodes.json'])[0].targets, ['authoritative-follower-service:20446']);
  network.status.inventoryReady = false;
  assert.throws(() => renderObservability(network, {eventToken: 'c'.repeat(64)}), /complete admitted inventory/);
});

test('renderer scrapes admitted Bitcoin policy clocks with topology identity', () => {
  const network = {
    apiVersion: 'testing.stacks.org/v1beta1', kind: 'StacksNetwork',
    metadata: {name: 'multi-bitcoin', namespace: 'hacknet-system', generation: 4},
    status: {
      phase: 'Ready', observedGeneration: 4, inventoryReady: true,
      inventoryDigest: `sha256:${'a'.repeat(64)}`,
      actors: [
        {name: 'bitcoin-a', role: 'burnchain', image: 'bitcoin:25', serviceName: 'multi-bitcoin-bitcoin-a', identityReady: true, runtimeImageID: `sha256:${'b'.repeat(64)}`},
        {name: 'follower-a', role: 'follower', image: 'stacks:main', serviceName: 'multi-bitcoin-follower-a', identityReady: true, runtimeImageID: `sha256:${'c'.repeat(64)}`},
      ],
      burnchainTopology: {
        digest: `sha256:${'d'.repeat(64)}`, observedGeneration: 4,
        nodes: [{name: 'bitcoin-a', policyRef: 'bitcoin-a-policy', policyUID: 'policy-uid', policyServiceName: 'bitcoin-a-policy-clock'}],
      },
    },
  };
  const rendered = renderObservability(network, {eventToken: 'c'.repeat(64)});
  const prometheus = rendered.items.find(item => item.kind === 'ConfigMap'
    && item.metadata.name === 'multi-bitcoin-attacknet-prometheus');
  const targets = JSON.parse(prometheus.data['burnchains.json']);
  assert.deepEqual(targets, [{targets: ['bitcoin-a-policy-clock:18500'], labels: {
    attacknet_network: 'multi-bitcoin', attacknet_actor: 'bitcoin-a', attacknet_role: 'burnchain',
    burnchain_policy: 'bitcoin-a-policy', burnchain_policy_uid: 'policy-uid',
    evidence_source: 'actor_self_reported',
  }}]);
  assert.match(prometheus.data['prometheus.yml'], /job_name: attacknet-burnchain-clock/);
});

test('render emits actor-labelled scrape targets and restricted credential-free observers', () => {
  const rendered = render();
  const resources = new Map(rendered.items.map(item => [`${item.kind}/${item.metadata.name}`, item]));
  const prometheus = resources.get('ConfigMap/attacknet-test-attacknet-prometheus');
  const nodes = JSON.parse(prometheus.data['nodes.json']);
  const signers = JSON.parse(prometheus.data['signers.json']);
  assert.deepEqual(nodes.map(item => item.targets[0]), [
    'attacknet-test-miner-1:20446',
    'attacknet-test-signer-node-1:20446',
    'attacknet-test-follower-1:20446',
  ]);
  assert.equal(nodes[1].labels.attacknet_role, 'companion');
  assert.equal(nodes[1].labels.evidence_source, 'actor_self_reported');
  assert.equal(nodes[0].labels.requested_image, 'stacks:patched');
  assert.equal(nodes[0].labels.instrumentation_profile, 'patched-main');
  assert.equal(nodes[0].labels.instrumentation_provenance, 'mixed');
  assert.equal(Object.keys(nodes[0].labels).some(label => /^instrumentation_m\d+_provenance$/.test(label)), false);
  assert.equal(nodes[0].labels.event_dispatch_mode, 'queued');
  assert.equal(nodes[1].labels.instrumentation_provenance, 'unavailable');
  assert.equal(signers[0].targets[0], 'attacknet-test-signer-1:31000');
  assert.match(prometheus.data['prometheus.yml'], /attacknet-orchestrator-events/);
  assert.match(prometheus.data['prometheus.yml'], /job_name: attacknet-run-controller/);
  assert.match(prometheus.data['prometheus.yml'], /targets: \["hacknet-run:8080"\]/);
  assert.match(prometheus.data['prometheus.yml'], /attacknet\.rules\.yml/);
  for (const alert of [
    'AttacknetInstrumentationProvenanceExporterAbsent',
    'AttacknetActorMetricsUnreachable',
    'AttacknetOrchestratorMetricsCollectionFailed',
    'AttacknetCorrelatedSignerParticipationLoss', 'AttacknetSignerStateFrozen',
    'AttacknetSignerValidationUnavailable', 'AttacknetNakamotoPropagationFailure',
  ]) assert.match(prometheus.data['attacknet.rules.yml'], new RegExp(alert));
  const actorScrapeJobs = [...prometheus.data['prometheus.yml'].matchAll(
    /^\s*- job_name: (stacks-(?:node|signer)-metrics)$/gm,
  )].map(match => match[1]).sort();
  const watchdogJobs = prometheus.data['attacknet.rules.yml']
    .match(/absent\(attacknet_instrumentation_family_provenance\) and on\(\) \(count\(up\{job=~"([^"]+)"\}\) > 0\)/)?.[1]
    .split('|').sort();
  assert.deepEqual(watchdogJobs, actorScrapeJobs);
  const unreachableJobs = prometheus.data['attacknet.rules.yml']
    .match(/AttacknetActorMetricsUnreachable[\s\S]*?up\{job=~"([^"]+)"\} == 0/)?.[1]
    .split('|').sort();
  assert.deepEqual(unreachableJobs, actorScrapeJobs);
  assert.match(prometheus.data['attacknet.rules.yml'], /AttacknetActorMetricsUnreachable[\s\S]*?for: 30s/);
  assert.match(prometheus.data['attacknet.rules.yml'], /AttacknetOrchestratorMetricsCollectionFailed[\s\S]*?attacknet_orchestrator_metrics_collection_success == 0/);
  assert.match(prometheus.data['attacknet.rules.yml'], /AttacknetOrchestratorMetricsCollectionFailed[\s\S]*?up\{job="attacknet-run-controller"\} == 1/);
  assert.match(
    prometheus.data['attacknet.rules.yml'],
    /AttacknetInstrumentationProvenanceExporterAbsent[\s\S]*?for: 2m/,
  );
  assert.match(prometheus.data['attacknet.rules.yml'], /classification="unavailable"/);
  assert.match(prometheus.data['attacknet.rules.yml'], /outcome=~"failed\|error\|rejected"/);
  assert.match(prometheus.data['attacknet.rules.yml'], /attacknet_instrumentation_family_provenance\{family="M19",provenance=~"merged\|attacknet-patch",attacknet_role=~"miner",evidence_source="orchestrator_observed"/);
  assert.match(prometheus.data['attacknet.rules.yml'], /AttacknetInstrumentationAbsentM15[\s\S]*?stacks_signer_policy_evaluations\)/);
  assert.doesNotMatch(prometheus.data['attacknet.rules.yml'], /stacks_signer_policy_evaluations_total/);
  assert.doesNotMatch(prometheus.data['attacknet.rules.yml'], /stacks_node_nakamoto_block_transfers_total/);
  assert.match(prometheus.data['attacknet.rules.yml'], /AttacknetInstrumentationAbsentM21[\s\S]*?stacks_node_signer_coordinator_milestone_seconds_count\)/);
  assert.doesNotMatch(prometheus.data['attacknet.rules.yml'], /instrumentation_m19_provenance/);
  assert.doesNotMatch(prometheus.data['attacknet.rules.yml'], /instrumentation_provenance!="unavailable"/);

  const events = resources.get('ConfigMap/attacknet-test-attacknet-events');
  const provenance = JSON.parse(events.data['instrumentation-provenance.json']);
  assert.equal(provenance.schema, 'stacks-attacknet-instrumentation-provenance/v1');
  const miner = provenance.actors.find(actor => actor.actor === 'miner-1');
  assert.equal(miner.families.find(family => family.family === 'M19').provenance, 'unavailable');
  assert.equal(miner.families.find(family => family.family === 'M20').provenance, 'attacknet-patch');
  const companion = provenance.actors.find(actor => actor.actor === 'signer-node-1');
  assert.ok(companion.families.every(family => family.provenance === 'unavailable'));

  for (const name of ['events', 'prometheus', 'grafana']) {
    const deployment = resources.get(`Deployment/attacknet-test-attacknet-${name}`);
    assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);
    assert.equal(deployment.spec.template.spec.securityContext.runAsNonRoot, true);
    assert.match(deployment.spec.template.metadata.annotations['testing.stacks.org/config-sha256'], /^[0-9a-f]{64}$/);
    for (const container of deployment.spec.template.spec.containers) {
      assert.equal(container.securityContext.allowPrivilegeEscalation, false);
      assert.equal(container.securityContext.readOnlyRootFilesystem, true);
      assert.deepEqual(container.securityContext.capabilities.drop, ['ALL']);
    }
  }
  const secretName = 'attacknet-test-attacknet-event-writer';
  assert.equal(resources.get(`Secret/${secretName}`).stringData.token, 'c'.repeat(64));
  const deployments = rendered.items.filter(item => item.kind === 'Deployment');
  const secretConsumers = deployments.filter(deployment =>
    deployment.spec.template.spec.volumes.some(volume => volume.secret?.secretName === secretName));
  assert.deepEqual(secretConsumers.map(deployment => deployment.metadata.name), ['attacknet-test-attacknet-events']);
  const eventContainer = resources.get('Deployment/attacknet-test-attacknet-events').spec.template.spec.containers[0];
  assert.ok(eventContainer.command.includes('--instrumentation-provenance=/opt/attacknet/instrumentation-provenance.json'));
  assert.ok(eventContainer.volumeMounts.some(mount => mount.subPath === 'instrumentation-provenance.json' && mount.readOnly));

  const lokiPolicy = resources.get('NetworkPolicy/attacknet-test-attacknet-loki-ingress');
  assert.deepEqual(lokiPolicy.spec.podSelector.matchLabels, labelsFor('attacknet-test', 'loki'));
  assert.deepEqual(lokiPolicy.spec.policyTypes, ['Ingress']);
  assert.deepEqual(
    lokiPolicy.spec.ingress[0].from.map(peer => peer.podSelector.matchLabels).sort(labelSort),
    [
      {'testing.stacks.org/network': 'attacknet-test', 'testing.stacks.org/loki-writer': 'true'},
      labelsFor('attacknet-test', 'grafana'),
    ].sort(labelSort),
  );
  assert.deepEqual(lokiPolicy.spec.ingress[0].ports, [{protocol: 'TCP', port: 3100}]);
});

test('run-controller metrics target is explicit and cannot inject Prometheus config', () => {
  const rendered = render({runOperatorTarget: 'custom-run.hacknet-system.svc:8080'});
  const prometheus = rendered.items.find(item => item.kind === 'ConfigMap'
    && item.metadata.name === 'attacknet-test-attacknet-prometheus');
  assert.match(prometheus.data['prometheus.yml'], /custom-run\.hacknet-system\.svc:8080/);
  assert.throws(() => renderObservability(manifest, {
    eventToken: 'c'.repeat(64), instrumentationExpectations,
    runOperatorTarget: 'run:8080\n  - job_name: forged',
  }), /bounded DNS name/);
});

test('mixed instrumentation requires exact per-family expectations', () => {
  assert.throws(() => renderObservability(manifest, {eventToken: 'c'.repeat(64)}), /lacks per-family expectations/);
  const invalid = structuredClone(instrumentationExpectations);
  invalid[0].families[0].provenance = 'mixed';
  assert.throws(() => renderObservability(manifest, {
    eventToken: 'c'.repeat(64), instrumentationExpectations: invalid,
  }), /invalid .* provenance/);
  const incomplete = structuredClone(instrumentationExpectations);
  incomplete[0].families.pop();
  assert.throws(() => renderObservability(manifest, {
    eventToken: 'c'.repeat(64), instrumentationExpectations: incomplete,
  }), /instrumentation expectation omits/);
});

test('per-family expectations come only from a digest-bound qualification plan', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-instrumentation-plan-'));
  const manifestPath = join(directory, 'manifest.json');
  writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
  const plan = {
    schema: 'stacks-attacknet-phase-1-qualification-plan/v1',
    renderedManifest: {path: manifestPath, digest: sha256File(manifestPath)},
    instrumentationFamilyExpectations: instrumentationExpectations,
  };
  plan.planDigest = sha256Value(plan);
  assert.deepEqual(instrumentationExpectationsFromPlan(plan, manifestPath), instrumentationExpectations);
  writeFileSync(manifestPath, `${JSON.stringify({...manifest, network: 'changed'})}\n`);
  assert.throws(() => instrumentationExpectationsFromPlan(plan, manifestPath), /does not bind the rendered manifest/);
  plan.instrumentationFamilyExpectations[0].families[0].provenance = 'merged';
  assert.throws(() => instrumentationExpectationsFromPlan(plan), /plan digest mismatch/);
});

test('render centralizes actor logs with collector-attached Kubernetes identity and bounded retention', () => {
  const rendered = render();
  const resources = new Map(rendered.items.map(item => [`${item.kind}/${item.metadata.name}`, item]));
  const loki = resources.get('ConfigMap/attacknet-test-attacknet-loki');
  assert.match(loki.data['loki.yaml'], /retention_period: 168h/);
  assert.match(loki.data['loki.yaml'], /retention_enabled: true/);
  assert.match(loki.data['loki.yaml'], /delete_request_store: filesystem/);
  assert.equal(resources.get('PersistentVolumeClaim/attacknet-test-attacknet-loki').spec.resources.requests.storage, '5Gi');

  const alloy = resources.get('ConfigMap/attacknet-test-attacknet-alloy').data['config.alloy'];
  assert.match(alloy, /spec\.nodeName=" \+ sys\.env\("NODE_NAME"\)/);
  assert.match(alloy, /testing\.stacks\.org\/network=attacknet-test/);
  for (const label of [
    'attacknet_network', 'attacknet_actor', 'attacknet_role', 'k8s_namespace', 'k8s_pod_uid',
    'k8s_node', 'k8s_container', 'requested_image', 'resolved_container_id',
    'log_content_trust', 'metadata_trust',
  ]) assert.match(alloy, new RegExp(`target_label\\s+= "${label}"`));
  assert.match(alloy, /actor_self_reported_untrusted/);
  assert.match(alloy, /kubernetes_collector_attached/);
  assert.doesNotMatch(alloy, /loki\.process|stage\.|json|logfmt/);

  const role = resources.get('Role/attacknet-test-attacknet-alloy');
  assert.deepEqual(role.rules, [
    {apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'watch']},
    {apiGroups: [''], resources: ['pods/log'], verbs: ['get']},
  ]);
  const daemonSet = resources.get('DaemonSet/attacknet-test-attacknet-alloy');
  assert.equal(daemonSet.spec.template.metadata.labels['testing.stacks.org/loki-writer'], 'true');
  assert.equal(daemonSet.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(daemonSet.spec.template.spec.securityContext.runAsNonRoot, true);
  assert.ok(daemonSet.spec.template.spec.volumes.some(volume => volume.name === 'service-account' && volume.projected));
  assert.ok(!daemonSet.spec.template.spec.volumes.some(volume => volume.hostPath));
  assert.ok(daemonSet.spec.template.spec.tolerations.every(toleration => toleration.key?.startsWith('node-role.kubernetes.io/')));
  assert.equal(daemonSet.spec.template.spec.containers[0].resources.limits.memory, '512Mi');
  assert.equal(daemonSet.spec.template.spec.containers[0].resources.limits['ephemeral-storage'], '256Mi');
  assert.equal(daemonSet.spec.template.spec.volumes.find(volume => volume.name === 'state').emptyDir.sizeLimit, '128Mi');

  const datasource = resources.get('ConfigMap/attacknet-test-attacknet-grafana').data['datasource.yaml'];
  assert.match(datasource, /uid: attacknet-loki/);
  const grafana = resources.get('ConfigMap/attacknet-test-attacknet-grafana');
  assert.ok(grafana.data['attacknet-actor.json']);
  const dashboard = JSON.parse(grafana.data['attacknet-overview.json']);
  const logsPanel = dashboard.panels.find(panel => panel.type === 'logs');
  assert.equal(logsPanel.datasource.uid, 'attacknet-loki');
  assert.match(logsPanel.description, /actor-self-reported/);
  assert.match(logsPanel.targets[0].expr, /attacknet_actor/);
  const protocolSources = dashboard.panels.find(panel => panel.id === 33);
  assert.equal(protocolSources.type, 'table');
  assert.deepEqual(protocolSources.targets.map(target => target.expr), [
    'attacknet_run_protocol_assertion_source_info{network="$network"}',
    'attacknet_run_protocol_assertion_source_observed_timestamp_seconds{network="$network"}',
  ]);
  const actorDashboard = JSON.parse(grafana.data['attacknet-actor.json']);
  assert.equal(actorDashboard.uid, 'stacks-attacknet-actor');
  const grafanaDeployment = resources.get('Deployment/attacknet-test-attacknet-grafana');
  assert.ok(grafanaDeployment.spec.template.spec.containers[0].volumeMounts.some(
    mount => mount.mountPath.endsWith('/attacknet-actor.json') && mount.readOnly === true));
});

test('render resolves long logical actor names exactly like bounded Kubernetes children', () => {
  const longManifest = {
    network: 'experiment-with-a-very-long-but-valid-network-name',
    namespace: 'hacknet-system',
    workloads: [{service: 'signer-node-with-an-equally-long-logical-name', type: 'node', role: 'companion'}],
  };
  const rendered = renderObservability(longManifest, {eventToken: 'c'.repeat(64)});
  for (const item of rendered.items) assert.ok(item.metadata.name.length <= 63, item.metadata.name);
  const prometheus = rendered.items.find(item => item.kind === 'ConfigMap' && item.metadata.labels['app.kubernetes.io/name'] === 'attacknet-prometheus');
  const target = JSON.parse(prometheus.data['nodes.json'])[0].targets[0].split(':')[0];
  assert.ok(target.length <= 63);
  assert.match(target, /-[0-9a-f]{8}$/);
});

test('standalone report escapes payloads and includes trust-boundary language', () => {
  const html = renderReport([{
    schemaVersion: 1,
    sequence: 1,
    runId: 'run-1',
    network: 'attacknet-test',
    kind: 'note',
    phase: 'verification',
    occurredAt: '2026-08-15T00:00:00.000Z',
    recordedAt: '2026-08-15T00:00:00.001Z',
    details: {message: '</script><script>alert(1)</script>'},
  }]);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /orchestrator-observed and bearer-authenticated/);
  assert.match(html, /actor-self-reported/);
});

test('report reader accepts multi-line JSONL beginning with an object', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-report-'));
  const path = join(directory, 'events.jsonl');
  writeFileSync(path, '{"sequence":1,"kind":"one"}\n{"sequence":2,"kind":"two"}\n');
  assert.deepEqual(readEvents(path).map(event => event.kind), ['one', 'two']);
});
