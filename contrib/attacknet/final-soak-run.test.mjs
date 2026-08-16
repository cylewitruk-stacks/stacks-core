import assert from 'node:assert/strict';
import test from 'node:test';

import {compileCampaign} from './fault-campaign.mjs';
import {buildFinalSoakRun} from './final-soak-run.mjs';
import {buildTopology} from './topology.mjs';

function manifest(network = 'attacknet-final') {
  const topology = buildTopology({minerCount: 3, signerCount: 10, followerCount: 5});
  return {
    network, namespace: 'hacknet-system',
    actors: topology.actors.map(actor => ({
      service: actor.name,
      role: actor.role,
      signerIndex: actor.signerIndex,
      signerWeight: actor.signerWeight,
    })),
  };
}

test('renders a finite serialized full-topology acceptance sequence', () => {
  const resource = buildFinalSoakRun({
    network: 'attacknet-final', name: 'acceptance', seed: 'repeatable-001',
  });
  assert.equal(resource.kind, 'List');
  assert.equal(resource.items.length, 5);
  const campaigns = resource.items.filter(item => item.kind === 'FaultCampaign');
  const run = resource.items.find(item => item.kind === 'AttacknetRun');
  assert.equal(campaigns.length, 4);
  assert.equal(campaigns.every(item => item.spec.template === true), true);
  assert.deepEqual(campaigns.map(item => item.spec.fault.type),
    ['pod', 'network', 'dns', 'io-pressure']);
  assert.deepEqual(run.spec.sequence.map(item => item.campaign),
    ['pod-restart', 'network-delay', 'dns-error', 'io-pressure']);
  assert.equal(run.spec.budgets.maxActiveFaults, 1);
  assert.equal(run.spec.budgets.maxBurnchainFaults, 0);
  assert.equal(run.spec.budgets.maxInconclusiveCampaigns, 0);
});

test('every acceptance campaign compiles against the proven full topology', () => {
  const network = 'attacknet-final';
  const resource = buildFinalSoakRun({network, name: 'acceptance'});
  const compiled = resource.items.filter(item => item.kind === 'FaultCampaign')
    .map(item => compileCampaign(item, manifest(network)));
  assert.deepEqual(compiled.map(item => item.resource.kind),
    ['PodChaos', 'NetworkChaos', 'DNSChaos', 'IOPressurePod']);
  assert.deepEqual(compiled[1].evidence.peerSelectedActors, ['miner-1']);
  assert.equal(compiled[0].evidence.signerImpact.affectedWeight, 1);
  assert.equal(compiled.every(item => !item.evidence.selectedActors.includes('bitcoin')), true);
});

test('rejects names that cannot produce bounded Kubernetes child names', () => {
  assert.throws(() => buildFinalSoakRun({name: `a${'b'.repeat(40)}`}), /at most 40/);
  assert.throws(() => buildFinalSoakRun({seed: ''}), /non-empty string/);
});
