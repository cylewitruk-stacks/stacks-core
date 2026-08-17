import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

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
  for (const metric of [
    'stacks_signer_runloop_ready',
    'stacks_signer_registered_for_current_reward_cycle',
    'stacks_signer_registered_for_next_reward_cycle',
    'stacks_signer_state_burn_block_height',
    'stacks_signer_state_last_changed_timestamp_seconds',
    'stacks_signer_companion_burn_block_height',
    'stacks_signer_pending_block_validations',
    'stacks_signer_global_state_available',
    'stacks_signer_global_state_total_weight',
    'stacks_signer_global_state_known_weight',
    'stacks_signer_global_state_maximum_view_weight',
    'stacks_signer_global_state_evaluator_threshold_weight',
    'stacks_signer_global_state_canonical_threshold_weight',
    'stacks_signer_block_proposals_received',
    'stacks_signer_policy_evaluations_total',
    'stacks_signer_policy_rejections_total',
    'stacks_signer_block_validation_lifecycle_total',
    'stacks_signer_block_response_deliveries_total',
    'stacks_node_signer_coordinator_rounds_total',
    'stacks_node_signer_response_weight_total',
    'stacks_node_signer_coordinator_milestone_seconds_bucket',
    'stacks_node_nakamoto_block_transfers_total',
  ]) assert.match(dashboardText, new RegExp(metric), `missing Workstream M metric ${metric}`);

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

test('histogram units and counter queries preserve exported metric semantics', () => {
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
        if (/stacks_(?:node|signer)_[a-z_]+(?:_total|_received|_sent)\{/.test(target.expr)
            && !target.expr.includes('stacks_node_active_miners_total')) {
          assert.match(target.expr, /rate\(/, `${panel.title} must render counters as change rates`);
        }
      }
    }
  }
});
