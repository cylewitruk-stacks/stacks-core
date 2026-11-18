import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

import {FEDERATION_SERIES_NAMES} from './federation_projection.js';

const root = new URL('../../federation/', import.meta.url);
const schema = JSON.parse(readFileSync(new URL('schema.json', root), 'utf8')) as {
  metricNames: string[];
  metricLabelKeys: string[];
  trustedResourceKeys: string[];
};
const agent = readFileSync(new URL('agent.yaml', root), 'utf8');
const collector = readFileSync(new URL('collector.yaml', root), 'utf8');

test('machine schema is represented at both privacy boundaries', () => {
  for (const [boundary, config] of [['actor', agent], ['central', collector]] as const) {
    assert.deepEqual(extractMetricAllowlist(config), [...schema.metricNames].sort(),
      `${boundary} metric allowlist differs from the machine schema`);
    assert.deepEqual(extractLabelAllowlist(config), [...schema.metricLabelKeys].sort(),
      `${boundary} label allowlist differs from the machine schema`);
  }
  for (const key of schema.trustedResourceKeys) {
    assert.match(collector, new RegExp(`key: ${escapeRegex(key)}(?:,|\\})`),
      `${key} absent from server-authored resources`);
  }
  assert.deepEqual(extractDatapointFilters(agent), extractDatapointFilters(collector),
    'actor and central label-value validation differ');
  assert.ok(extractDatapointFilters(collector).some(filter =>
    filter.includes('signer_public_key') && filter.includes('(02|03)[0-9a-f]{64}')),
  'central boundary does not validate signer public-key labels');
  assert.ok(extractDatapointFilters(collector).some(filter =>
    filter.includes('peer_id') && filter.includes('[1-9A-HJ-NP-Za-km-z]{32,128}')),
  'central boundary does not validate bounded transport PeerId labels');
});

test('trace federation is structurally absent pending serialized privacy audit', () => {
  for (const config of [agent, collector]) {
    assert.doesNotMatch(config, /\/v1\/traces|pipelines:\s*\n\s*traces:/);
  }
});

test('observer query covers every exported series in the machine metric contract', () => {
  const counters = new Set([
    'stacks_signer_agreement_state_change_reasons',
    'stacks_signer_agreement_state_conflicts',
    'stacks_signer_block_policy_rejections',
    'stacks_signer_block_proposals_received',
    'stacks_signer_block_responses_sent',
    'stacks_signer_block_validation_responses',
    'stacks_signer_deferred_miner_authorization_observations',
    'stacks_signer_deferred_miner_authorizations_admitted',
    'stacks_signer_deferred_miner_authorizations_resolved',
  ]);
  const histograms = new Set([
    'stacks_node_block_proposal_validation_execution_seconds',
    'stacks_signer_block_response_latencies_histogram',
    'stacks_signer_block_validation_latencies_histogram',
  ]);
  const exported = schema.metricNames.flatMap(name => histograms.has(name)
    ? [`${name}_bucket`, `${name}_count`, `${name}_sum`]
    : counters.has(name) ? [`${name}_total`] : [name]);
  assert.deepEqual([...FEDERATION_SERIES_NAMES].sort(), exported.sort());
});

function extractMetricAllowlist(config: string): string[] {
  const match = config.match(/not IsMatch\(name, "\^\(([^\"]+)\)\$"\)/);
  assert.ok(match?.[1], 'metric filter regex is absent');
  return match[1].split('|').sort();
}

function extractLabelAllowlist(config: string): string[] {
  const match = config.match(/keep_keys\(datapoint\.attributes, (\[[^\]]+\])\)/);
  assert.ok(match?.[1], 'datapoint label allowlist is absent');
  return (JSON.parse(match[1]) as string[]).sort();
}

function extractDatapointFilters(config: string): string[] {
  const section = config.match(/\n\s+datapoint:\n((?:\s+- '[^\n]+'\n?)+)/);
  assert.ok(section?.[1], 'datapoint value filters are absent');
  return [...section[1].matchAll(/- '([^']+)'/g)].map(match => match[1]!).sort();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
