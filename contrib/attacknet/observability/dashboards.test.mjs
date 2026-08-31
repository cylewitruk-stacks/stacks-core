import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {loadInventory} from '../instrumentation/capability-manifest.mjs';
import {prometheusRules, validatePrometheusRulesAgainstInventory} from './render.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));

function readDashboard(name) {
  return JSON.parse(readFileSync(join(ROOT, 'dashboards', name), 'utf8'));
}

function allTargets(dashboard) {
  return dashboard.panels.flatMap(panel => panel.targets ?? []);
}

function validateDashboard(dashboard) {
  assert.ok(Number(dashboard.schemaVersion) >= 40);
  assert.match(dashboard.uid, /^stacks-attacknet-/);
  assert.ok(dashboard.panels.length > 0);
  assert.equal(new Set(dashboard.panels.map(panel => panel.id)).size, dashboard.panels.length, 'panel IDs must be unique');
  for (const panel of dashboard.panels) {
    assert.ok(panel.title, `panel ${panel.id} has a title`);
    assert.ok(panel.description, `panel ${panel.id} explains its diagnostic and trust semantics`);
    assert.ok(['prometheus', 'loki'].includes(panel.datasource?.type), `panel ${panel.id} uses a provisioned datasource`);
    for (const target of panel.targets ?? []) {
      assert.ok(target.expr, `panel ${panel.id} target ${target.refId} has a query`);
      if (panel.datasource.type === 'loki') assert.equal(panel.datasource.uid, 'attacknet-loki');
      else assert.equal(panel.datasource.uid, 'attacknet-prometheus');
    }
  }
  const variables = new Set(dashboard.templating.list.map(variable => variable.name));
  assert.ok(variables.has('network'));
  assert.ok(variables.has('actor'));
}

test('network and actor dashboards satisfy provisioning and drill-down contract', () => {
  const overview = readDashboard('attacknet-overview.json');
  const actor = readDashboard('attacknet-actor.json');
  validateDashboard(overview);
  validateDashboard(actor);
  assert.notEqual(overview.uid, actor.uid);
  assert.ok(overview.links.some(link => link.url.includes(actor.uid)));
  assert.ok(actor.links.some(link => link.url.includes(overview.uid)));
  assert.ok(overview.templating.list.some(variable => variable.name === 'role'));
  assert.equal(actor.templating.list.find(variable => variable.name === 'actor').multi, false);
});

test('dashboards distinguish trusted orchestration evidence from actor self-reports', () => {
  for (const dashboard of [readDashboard('attacknet-overview.json'), readDashboard('attacknet-actor.json')]) {
    const text = JSON.stringify(dashboard);
    assert.match(text, /orchestrator[- ]observed|trusted (?:orchestration|runtime|Kubernetes)/i);
    assert.match(text, /self-reported/i);
    const logPanels = dashboard.panels.filter(panel => panel.type === 'logs');
    assert.equal(logPanels.length, 1);
    assert.match(logPanels[0].description, /untrusted/i);
    assert.match(logPanels[0].targets[0].expr, /attacknet_network=.*attacknet_actor=/);
  }
});

test('actor dashboard covers node, signer, miner, fault, runtime, and log diagnostics', () => {
  const actor = readDashboard('attacknet-actor.json');
  const expressions = allTargets(actor).map(target => target.expr).join('\n');
  for (const required of [
    'attacknet_actor_info',
    'attacknet_actor_ready',
    'attacknet_fault_active',
    'stacks_node_burn_block_height',
    'stacks_node_neighbors_inbound',
    'stacks_node_stx_blocks_processed_total',
    'stacks_node_miner_stop_reason_total',
    'stacks_signer_runloop_ready',
    'stacks_signer_registered_for_current_reward_cycle',
    'stacks_signer_block_validation_responses',
    'stacks_signer_block_response_latencies_histogram_bucket',
  ]) assert.match(expressions, new RegExp(required));
  assert.ok(actor.panels.some(panel => panel.type === 'state-timeline'));
  assert.ok(actor.panels.some(panel => panel.type === 'bargauge'));
  assert.ok(actor.panels.some(panel => panel.type === 'table'));
  assert.ok(actor.panels.some(panel => panel.type === 'logs'));
});

test('dashboard queries cover every current-main node and signer metric family', () => {
  const dashboardText = [
    readFileSync(join(ROOT, 'dashboards', 'attacknet-overview.json'), 'utf8'),
    readFileSync(join(ROOT, 'dashboards', 'attacknet-actor.json'), 'utf8'),
  ].join('\n');
  const sources = [
    join(ROOT, '..', '..', '..', 'stackslib', 'src', 'monitoring', 'prometheus.rs'),
    join(ROOT, '..', '..', '..', 'stacks-signer', 'src', 'monitoring', 'prometheus.rs'),
  ];
  const exported = new Set(sources.flatMap(source =>
    [...readFileSync(source, 'utf8').matchAll(/"(stacks_(?:node|signer|contract|unreachable)[a-z0-9_]*)"/g)]
      .map(match => match[1])));
  assert.ok(exported.size >= 50, 'metric inventory unexpectedly shrank; inspect exporter changes');
  const missing = [...exported].filter(metric => !dashboardText.includes(metric));
  assert.deepEqual(missing, [], `dashboard coverage missing: ${missing.join(', ')}`);
});

test('dashboards cover the complete Workstream M contract without conflating chain scales', () => {
  const overview = readDashboard('attacknet-overview.json');
  const actor = readDashboard('attacknet-actor.json');
  const dashboardText = JSON.stringify([overview, actor]);
  for (const family of loadInventory().families) {
    assert.match(dashboardText, new RegExp(family.family), `missing Workstream M metric ${family.family}`);
  }

  assert.match(dashboardText, /proposal_to_first_response/);
  assert.match(dashboardText, /proposal_to_threshold/);

  const burnPanel = overview.panels.find(panel => panel.title === 'Burn-chain cohort progress');
  const stacksPanel = overview.panels.find(panel => panel.title === 'Stacks-chain cohort progress');
  assert.ok(burnPanel);
  assert.ok(stacksPanel);
  const burnQueries = JSON.stringify(burnPanel.targets);
  const stacksQueries = JSON.stringify(stacksPanel.targets);
  assert.match(burnQueries, /stacks_node_burn_block_height/);
  assert.doesNotMatch(burnQueries, /stacks_node_stacks_tip_height/);
  assert.match(stacksQueries, /stacks_node_stacks_tip_height/);
  assert.doesNotMatch(stacksQueries, /stacks_node_burn_block_height/);
});

test('multi-Bitcoin panels keep height, branch identity, work, and graph health on separate scales', () => {
  const overview = readDashboard('attacknet-overview.json');
  const expected = new Map([
    ['Bitcoin heights', 'attacknet_burnchain_clock_bitcoin_height'],
    ['Bitcoin graph health', 'attacknet_burnchain_clock_connected_peers'],
    ['Bitcoin branch fingerprints', 'attacknet_burnchain_clock_branch_fingerprint'],
    ['Bitcoin cumulative work (log2)', 'attacknet_burnchain_clock_chainwork_log2'],
  ]);
  for (const [title, metric] of expected) {
    const panel = overview.panels.find(candidate => candidate.title === title);
    assert.ok(panel, `missing ${title}`);
    const queries = JSON.stringify(panel.targets);
    assert.match(queries, new RegExp(metric));
    for (const other of expected.values()) {
      if (other !== metric && title !== 'Bitcoin graph health') assert.doesNotMatch(queries, new RegExp(other));
    }
  }
  const graph = overview.panels.find(panel => panel.title === 'Bitcoin graph health');
  assert.match(JSON.stringify(graph.targets), /attacknet_burnchain_clock_chain_tips/);

  const admitted = overview.panels.find(panel => panel.title === 'Admitted Bitcoin graph and Stacks bindings (trusted)');
  assert.ok(admitted);
  assert.equal(admitted.type, 'table');
  const admittedQueries = JSON.stringify(admitted.targets);
  assert.match(admittedQueries, /attacknet_burnchain_node_info/);
  assert.match(admittedQueries, /attacknet_burnchain_topology_edge_info/);
  assert.match(admittedQueries, /attacknet_burnchain_actor_binding_info/);
  assert.match(admitted.description, /trusted topology-operator/i);
  assert.deepEqual(admitted.transformations.map(transformation => transformation.id), ['merge', 'organize']);

  const stacksBurnViews = overview.panels.find(panel => panel.title === 'Bound Stacks burn-view fingerprints');
  assert.ok(stacksBurnViews);
  assert.match(JSON.stringify(stacksBurnViews.targets), /attacknet_run_stacks_burn_view_fingerprint/);
  assert.match(stacksBurnViews.description, /full consensus hashes.*structured protocol evidence/i);
});

test('Prometheus instrumentation rules resolve every family, label, and value through the inventory', () => {
  const inventory = loadInventory();
  assert.equal(validatePrometheusRulesAgainstInventory(prometheusRules(), inventory), true);
  assert.throws(() => validatePrometheusRulesAgainstInventory(
    'expr: rate(stacks_signer_policy_evaluations{classification="invented"}[2m])', inventory),
  /unknown M15.classification value invented/);
  assert.throws(() => validatePrometheusRulesAgainstInventory(
    'expr: rate(stacks_signer_policy_evaluations_total{classification="unavailable"}[2m])', inventory),
  /M15 as stacks_signer_policy_evaluations_total, not its exact exporter name/);
});

test('dashboards expose capability provenance and treat unavailable series as no data', () => {
  for (const dashboard of [readDashboard('attacknet-overview.json'), readDashboard('attacknet-actor.json')]) {
    const panel = dashboard.panels.find(candidate => candidate.title.includes('Instrumentation capability'));
    assert.ok(panel, `${dashboard.uid} lacks instrumentation capability panel`);
    const text = JSON.stringify(panel);
    assert.match(text, /instrumentation_profile/);
    assert.match(text, /instrumentation_provenance/);
    assert.match(text, /attacknet_instrumentation_family_provenance/);
    assert.match(text, /family/);
    assert.match(text, /provenance/);
    assert.match(text, /evidence_source/);
    assert.match(text, /requested_image/);
    assert.match(text, /event_dispatch_mode/);
    assert.match(panel.description, /unavailable.*(?:empty|gap|zero)/i);
    assert.match(panel.description, /sealed capability manifest/i);
  }
});

test('overview exposes identity-bound protocol gates and their terminal alert', () => {
  const overview = readDashboard('attacknet-overview.json');
  const panel = overview.panels.find(candidate => candidate.title === 'Protocol assertion gates (trusted)');
  assert.ok(panel);
  assert.equal(panel.type, 'state-timeline');
  assert.match(panel.description, /identity-bound/i);
  assert.match(panel.description, /Inconclusive/);
  assert.match(JSON.stringify(panel.targets), /attacknet_run_protocol_assertion/);
  assert.match(JSON.stringify(panel.targets), /\{\{gate\}\}/);
  assert.match(prometheusRules(), /AttacknetProtocolAssertionTerminalFailure/);
  assert.match(prometheusRules(), /outcome=~"Violated\|Inconclusive"/);
});

test('overview exposes trusted typed fault-action lifecycle state', () => {
  const overview = readDashboard('attacknet-overview.json');
  const panel = overview.panels.find(candidate => candidate.title === 'Typed fault action lifecycle (trusted)');
  assert.ok(panel);
  assert.equal(panel.type, 'state-timeline');
  assert.match(panel.description, /orchestrator-observed/i);
  assert.match(panel.description, /typed stage action/i);
  const targets = JSON.stringify(panel.targets);
  assert.match(targets, /attacknet_fault_action_info/);
  assert.match(targets, /\{\{stage\}\}\/\{\{action\}\}/);
  assert.match(targets, /\{\{phase\}\}/);
  assert.match(targets, /\{\{reason\}\}/);
});

test('dashboards separate admitted adversarial policy from actor-reported attempts', () => {
  for (const dashboard of [readDashboard('attacknet-overview.json'), readDashboard('attacknet-actor.json')]) {
    const admitted = dashboard.panels.find(panel => panel.title.includes('Adversarial') || panel.title.includes('adversarial'));
    const attempts = dashboard.panels.find(panel => panel.title === 'Deterministic policy state (self-reported)');
    assert.ok(admitted, `${dashboard.uid} lacks admitted adversarial identity`);
    assert.ok(attempts, `${dashboard.uid} lacks deterministic policy attempts`);
    assert.match(JSON.stringify(admitted.targets), /attacknet_adversarial_policy_info/);
    assert.match(admitted.description, /(?:operator|orchestration state)/i);
    assert.match(JSON.stringify(attempts.targets), /stacks_signer_attacknet_policy_matches_total/);
    assert.match(JSON.stringify(attempts.targets), /stacks_signer_attacknet_policy_evaluations/);
    assert.match(attempts.description, /self-reported|actor-controlled/i);
    assert.match(attempts.description, /cannot|not .* impact/i);
  }
});

test('histogram units and counter queries preserve exported metric semantics', () => {
  const counterFamilies = loadInventory().families
    .filter(family => family.type === 'counter')
    .map(family => family.family);
  for (const dashboard of [readDashboard('attacknet-overview.json'), readDashboard('attacknet-actor.json')]) {
    for (const panel of dashboard.panels) {
      const expressions = (panel.targets ?? []).map(target => target.expr).join('\n');
      if (/(?:latencies_histogram|mempool_tx_confirm_times)_bucket/.test(expressions)) {
        const hasSeconds = panel.fieldConfig.defaults.unit === 's' || panel.fieldConfig.overrides.some(
          override => override.properties?.some(property => property.id === 'unit' && property.value === 's'));
        assert.ok(hasSeconds, `${panel.title} must display seconds exported by Rust histograms`);
        assert.match(expressions, /histogram_quantile\(/);
      }
      for (const target of panel.targets ?? []) {
        for (const family of counterFamilies) {
          if (!target.expr.includes(family)) continue;
          assert.doesNotMatch(target.expr, new RegExp(`${family}_total\\b`),
            `${panel.title} must use the Rust exporter's exact counter family name`);
          assert.match(target.expr, /rate\(/, `${panel.title} must render ${family} as a change rate`);
        }
        if (/stacks_(?:node|signer)_[a-z_]+(?:_total|_received|_sent)\{/.test(target.expr)
            && !target.expr.includes('stacks_node_active_miners_total')) {
          assert.match(target.expr, /rate\(/, `${panel.title} must render counters as change rates`);
        }
      }
    }
  }
});
