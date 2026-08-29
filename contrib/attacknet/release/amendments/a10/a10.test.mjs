import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statfsSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  A10_STORAGE_MINIMUM_AVAILABLE_BYTES, validateA10AttacknetCheck, validateA10Campaign,
  validateA10HacknetCheck, validateA10NegativeControl, validateA10Network,
  validateA10EvidenceOutput, validateA10Incident, validateA10Policy, validateA10Run,
  validateA10StoragePreflight, validateA10Views,
} from './evidence.mjs';
import {A10_BUILD_PURPOSES, A10_INSTALLED_PURPOSES, validateA10CandidateBuild} from './qualification/candidate-build.mjs';
import {
  A10_SIGNER_SET_READY_HEIGHT, prepareQualificationOutput, stageQualificationCredentials,
} from './qualification/live.mjs';
import {
  A10_ATTESTATION_SCHEMA, A10_CHECK_IDS, A10_PARENT_REVISION,
  A10_VERIFICATION_SCHEMA, hostStoragePreflight, validateA10CandidateAttestation, validateA10Verification,
} from './verify.mjs';

const tree = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const observedAt = '2026-08-28T00:00:00.000Z';
const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');

function snapshot(kind, resource) {
  return {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status', resourceDigest: digest('1'),
    resource: {apiVersion: 'testing.stacks.org/v1beta1', kind, ...resource}};
}

function topology(network) {
  return snapshot('StacksNetwork', {metadata: {name: network, uid: `${network}-uid`, generation: 2}, status: {
    phase: 'Ready', inventoryReady: true, observedGeneration: 2, inventoryDigest: digest('2'),
    burnchainTopology: {schemaVersion: 'stacks-network-admitted-burnchain-topology/v1', digest: digest('3'),
      observedGeneration: 2, nodes: [
        {name: 'bitcoin-a', serviceName: `${network}-bitcoin-a`, rpcPort: 18443, p2pPort: 18444,
          peerRefs: ['bitcoin-b'], policyRef: `${network}-bitcoin-a`, policyUID: `${network}-bitcoin-a-uid`,
          policyServiceName: `${network}-bitcoin-a-clock`},
        {name: 'bitcoin-b', serviceName: `${network}-bitcoin-b`, rpcPort: 19443, p2pPort: 19444,
          peerRefs: ['bitcoin-a'], policyRef: `${network}-bitcoin-b`, policyUID: `${network}-bitcoin-b-uid`,
          policyServiceName: `${network}-bitcoin-b-clock`},
      ], bindings: [
        {actor: 'miner-1', bitcoinNodeRef: 'bitcoin-a'}, {actor: 'follower-1', bitcoinNodeRef: 'bitcoin-a'},
        {actor: 'follower-b', bitcoinNodeRef: 'bitcoin-b'}, {actor: 'signer-node-1', bitcoinNodeRef: 'bitcoin-a'},
      ]},
  }});
}

function policy(network, node) {
  return snapshot('BurnchainPolicy', {metadata: {name: `${network}-${node}`, uid: `${network}-${node}-uid`, generation: 1},
    spec: {networkRef: network, bitcoinNodeRef: node}, status: {phase: 'Ready', observedGeneration: 1,
      observedHeight: 222, appliedPolicyDigest: digest(node === 'bitcoin-a' ? '4' : '5')}});
}

function branchEvidence(values, stacks = false, stable = false) {
  const bitcoinObservations = Object.fromEntries(['bitcoin-a', 'bitcoin-b'].map((actor, index) => [actor, {
    height: 222, headers: 222, bestBlockHash: values[index], chainwork: 'de',
    source: {actor, evidenceClass: 'actor_self_reported'},
  }]));
  return {networkUID: 'network-uid', inventoryDigest: digest('2'), topologyDigest: digest('3'),
    observedAt, current: Object.fromEntries((stacks ? ['follower-1', 'follower-b'] : ['bitcoin-a', 'bitcoin-b'])
      .map((actor, index) => [actor, values[index]])), bitcoinObservations,
    bindings: stacks ? {'follower-1': 'bitcoin-a', 'follower-b': 'bitcoin-b'} : undefined,
    stacksObservations: stacks ? Object.fromEntries(['follower-1', 'follower-b'].map((actor, index) => [actor, {
      burnBlockHeight: 222, burnConsensusHash: values[index], bitcoinNodeRef: index ? 'bitcoin-b' : 'bitcoin-a',
      source: {actor, evidenceClass: 'actor_self_reported'},
    }])) : undefined,
    sources: [], stableSince: stable ? observedAt : undefined};
}

function run(network) {
  const result = (id, evidence) => ({id, outcome: 'Proven', evidence});
  return snapshot('AttacknetRun', {metadata: {name: `${network}-run`}, spec: {networkRef: network, seed: 'same-seed'}, status: {
    phase: 'Passed', cleanup: {completed: true}, budgetUsage: {burnchainFaults: 2},
    scheduleRef: {digest: digest('7')}, scheduleSummary: {}, protocolAssertions: {
      baseline: {outcome: 'Proven', results: [result('bitcoin-baseline', branchEvidence(['a', 'a'])), result('stacks-baseline', branchEvidence(['s', 's'], true))]},
      during: {outcome: 'Proven', results: [result('bitcoin-diverged', branchEvidence(['a', 'b'])), result('stacks-diverged', branchEvidence(['s', 't'], true))]},
      recovery: {outcome: 'Proven', results: [result('bitcoin-converged', branchEvidence(['c', 'c'], false, true)), result('stacks-converged', branchEvidence(['u', 'u'], true, true))]},
    },
  }});
}

function campaign(network) {
  return snapshot('FaultCampaign', {metadata: {name: `${network}-campaign`}, spec: {networkRef: network}, status: {
    phase: 'Passed', cleanup: {allRecovered: true}, stages: [
      {actions: [{id: 'partition-bitcoin-edge', phase: 'Completed', mutation: {kind: 'NetworkChaos'}}]},
      {actions: [{id: 'reorg-bitcoin-b', phase: 'Completed', mutation: {kind: 'BurnchainReorgWorker'},
        effectResults: [{assertion: 'BurnchainReorgProven', outcome: 'Proven', evidence: {
          schemaVersion: 'attacknet-burnchain-reorg-result/v1', canonicalProven: true,
          originalBranch: [{}, {}], replacementBranch: [{hash: '1'}, {hash: '2'}, {hash: '3'}],
          final: {bestblockhash: '3'},
        }}], recoveryResults: [{assertion: 'BurnchainPolicyRestored', outcome: 'Proven'}]}]},
    ],
  }});
}

function views(network) {
  return {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a10-node-views/v1',
    observedAt,
    network: {name: network, uid: `${network}-uid`, observedGeneration: 3,
      inventoryDigest: digest('2'), topologyDigest: digest('3')},
    bitcoin: ['bitcoin-a', 'bitcoin-b'].map(actor => ({actor, chain: 'regtest', blocks: 222, headers: 222,
      bestblockhash: 'f'.repeat(64), chainwork: 'd'.repeat(64), evidenceClass: 'actor_self_reported',
      peers: [{last_block: 1_700_000_000, last_transaction: 0}],
      networkUID: `${network}-uid`, inventoryDigest: digest('2'), topologyDigest: digest('3'),
      networkGeneration: 3,
      podName: `${network}-${actor}-0`, podUID: `${actor}-uid`, runtimeImageID: digest('8')})),
    stacks: [{actor: 'follower-1', bitcoinNodeRef: 'bitcoin-a'}, {actor: 'follower-b', bitcoinNodeRef: 'bitcoin-b'}]
      .map(value => ({...value, burnBlockHeight: 222, burnConsensusHash: 'e'.repeat(40),
        evidenceClass: 'actor_self_reported', networkUID: `${network}-uid`, inventoryDigest: digest('2'),
        topologyDigest: digest('3'), networkGeneration: 3,
        podName: `${network}-${value.actor}-0`, podUID: `${value.actor}-uid`,
        runtimeImageID: digest('8')}))};
}

test('A10 network, policies, run, campaign, and recovery views require independent proof', () => {
  assert.doesNotThrow(() => validateA10Network(topology('a10-qualification'), tree, 'a10-qualification'));
  assert.doesNotThrow(() => validateA10Policy(policy('a10-qualification', 'bitcoin-a'), tree, 'a10-qualification', 'bitcoin-a'));
  assert.doesNotThrow(() => validateA10Run(run('a10-qualification'), tree, 'a10-qualification'));
  assert.doesNotThrow(() => validateA10Campaign(campaign('a10-qualification'), tree, 'a10-qualification'));
  assert.doesNotThrow(() => validateA10Views(views('a10-qualification'), tree, 'a10-qualification'));

  const falseSplit = run('a10-qualification');
  falseSplit.resource.status.protocolAssertions.during.results[0].evidence.current['bitcoin-b'] = 'a';
  assert.throws(() => validateA10Run(falseSplit, tree, 'a10-qualification'), /split/);
  const wrongBinding = topology('a10-qualification');
  wrongBinding.resource.status.burnchainTopology.bindings.find(item => item.actor === 'follower-b').bitcoinNodeRef = 'bitcoin-a';
  assert.throws(() => validateA10Network(wrongBinding, tree, 'a10-qualification'), /topology/);
  const missingStacksHash = views('a10-qualification');
  delete missingStacksHash.stacks[0].burnConsensusHash;
  assert.throws(() => validateA10Views(missingStacksHash, tree, 'a10-qualification'), /incomplete or divergent/);
  const divergentStacksHash = views('a10-qualification');
  divergentStacksHash.stacks[1].burnConsensusHash = 'd'.repeat(40);
  assert.throws(() => validateA10Views(divergentStacksHash, tree, 'a10-qualification'), /incomplete or divergent/);
  const unboundBitcoin = views('a10-qualification');
  delete unboundBitcoin.bitcoin[0].podUID;
  assert.throws(() => validateA10Views(unboundBitcoin, tree, 'a10-qualification'), /incomplete or divergent/);
  const staleStacksIdentity = views('a10-qualification');
  staleStacksIdentity.stacks[0].inventoryDigest = digest('9');
  assert.throws(() => validateA10Views(staleStacksIdentity, tree, 'a10-qualification'), /incomplete or divergent/);
  const staleGeneration = views('a10-qualification');
  staleGeneration.bitcoin[0].networkGeneration = 2;
  assert.throws(() => validateA10Views(staleGeneration, tree, 'a10-qualification'), /incomplete or divergent/);
  const invalidPeerTiming = views('a10-qualification');
  invalidPeerTiming.bitcoin[0].peers[0].last_block = -1;
  assert.throws(() => validateA10Views(invalidPeerTiming, tree, 'a10-qualification'), /incomplete or divergent/);
});

test('topology drift negative control requires zero mutation and exact restoration', () => {
  const liveSource = readFileSync(join(amendmentDirectory, 'qualification/live.mjs'), 'utf8');
  assert.match(liveSource, /name: 'a10-topology-drift'[\s\S]*?allowBurnchain: true[\s\S]*?afterCampaignStart: '30s'/);
  for (const kind of ['persistentvolumeclaims', 'statefulsets.apps', 'services', 'deployments.apps', 'networkchaos.chaos-mesh.org']) {
    assert.ok(liveSource.includes(`count('${kind}'`), `clean-scope contract omits ${kind}`);
  }
  assert.match(liveSource, /waitFor\('A10 owned-resource teardown', scopeResidue, scopeIsClean, 300\)/);
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a10-topology-drift-control/v1',
    outcome: 'Passed', campaignPhase: 'Failed', campaignReason: 'AdmissionInputChanged',
    cleanupAbsent: true, cleanupAllRecovered: true,
    mutationsBefore: 0, mutationsAfter: 0, admittedTopologyDigest: digest('1'),
    changedTopologyDigest: digest('2'), restoredTopologyDigest: digest('1')};
  assert.doesNotThrow(() => validateA10NegativeControl(value, tree));
  assert.doesNotThrow(() => validateA10NegativeControl({...value,
    campaignPhase: 'Inconclusive', campaignReason: 'TargetIdentityDiverged'}, tree));
  assert.throws(() => validateA10NegativeControl({...value,
    campaignPhase: 'Failed', campaignReason: 'TargetIdentityDiverged'}, tree), /admission rejection/);
  value.mutationsAfter = 1;
  assert.throws(() => validateA10NegativeControl(value, tree), /zero mutation/);
});

test('storage and whole-product records fail closed', () => {
  const node = name => ({name, ok: true, rootFilesystem: {availableBytes: A10_STORAGE_MINIMUM_AVAILABLE_BYTES}, imageFilesystem: {availableBytes: A10_STORAGE_MINIMUM_AVAILABLE_BYTES}});
  const check = phase => ({phase, exitCode: 0, schemaVersion: 1, ok: true, source: 'kubelet-stats-summary',
    minimumAvailableBytes: A10_STORAGE_MINIMUM_AVAILABLE_BYTES,
    nodes: ['control-plane', 'worker', 'worker2'].map(node)});
  const storage = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a10-storage-preflight/v1',
    minimumAvailableBytes: A10_STORAGE_MINIMUM_AVAILABLE_BYTES, recordedAt: observedAt,
    checks: [check('before-build'), check('before-network')]};
  assert.doesNotThrow(() => validateA10StoragePreflight(storage, tree));
  storage.checks[1].nodes.pop();
  assert.throws(() => validateA10StoragePreflight(storage, tree), /before-network/);

  const attacknet = {schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: tree,
    status: 'passed', suites: [{name: 'release', tests: 1, passed: 1, failed: 0}]};
  const hacknet = {schemaVersion: 'stacks-hacknet-offline-check-result/v1', sourceRevision: tree,
    status: 'passed', requiredChecks: ['controller'], optionalChecks: ['go', 'envtest', 'helm'].map(name => ({name, status: 'passed'}))};
  assert.doesNotThrow(() => validateA10AttacknetCheck(attacknet, tree));
  assert.doesNotThrow(() => validateA10HacknetCheck(hacknet, tree));
});

function kindLoad(refs) {
  const nodes = ['kind-control-plane', 'kind-worker', 'kind-worker2'];
  return {schemaVersion: 'stacks-attacknet-kind-image-load/v1', outcome: 'Loaded',
    nodes: nodes.map(name => ({name, architecture: 'arm64'})), images: nodes.flatMap(node => refs.map((requestedRef, index) => ({node, requestedRef, runtimeImageID: digest(String((index % 9) + 1)), verified: true})))};
}

test('candidate build binds every image to all three arm64 kind nodes', () => {
  const buildImages = A10_BUILD_PURPOSES.map((purpose, index) => ({purpose, ref: `local/${purpose}:a10`, id: digest(String((index % 9) + 1))}));
  const installImages = A10_INSTALLED_PURPOSES.map(purpose => { const built = buildImages.find(image => image.purpose === purpose); return {purpose, deploymentRef: built.ref, id: built.id}; });
  const actorImages = ['stacks-core', 'stacker'].map(purpose => { const built = buildImages.find(image => image.purpose === purpose); return {purpose, ref: built.ref, immutableID: built.id}; });
  const value = {schemaVersion: 'stacks-attacknet-a10-candidate-build/v1', qualifiedTree: tree, capturedAt: observedAt,
    build: {schemaVersion: 'stacks-attacknet-local-build/v1', images: buildImages},
    install: {schemaVersion: 'stacks-attacknet-local-install/v1', images: installImages, kindImageLoad: kindLoad(installImages.map(image => image.deploymentRef))},
    actorImages, actorImageLoad: kindLoad(actorImages.map(image => image.ref)),
    runOperatorImageID: buildImages.find(image => image.purpose === 'run-operator').id};
  assert.doesNotThrow(() => validateA10CandidateBuild(value, tree));
  value.actorImageLoad.images.pop();
  assert.throws(() => validateA10CandidateBuild(value, tree), /incomplete/);
});

test('verification, attestation, and contract are exact-tree contracts', () => {
  const verification = {schema: A10_VERIFICATION_SCHEMA, qualifiedTree: tree,
    parentRevision: A10_PARENT_REVISION, patchDigest: digest('6'), outcome: 'Passed', recordedAt: observedAt,
    checks: A10_CHECK_IDS.map(id => ({id, status: 'passed', command: id, cwd: '.', startedAt: observedAt,
      durationMs: 1, exitCode: 0, outputDigest: digest('7'), stdout: '', stderr: ''}))};
  assert.doesNotThrow(() => validateA10Verification(verification, tree));
  const attestation = {schema: A10_ATTESTATION_SCHEMA, candidateRevision: 'b'.repeat(40), candidateTree: tree,
    parentRevision: A10_PARENT_REVISION, patchDigest: verification.patchDigest,
    evidenceSummaryDigest: digest('8'), signatureVerified: true, recordedAt: observedAt};
  assert.doesNotThrow(() => validateA10CandidateAttestation(attestation, {qualifiedTree: tree,
    patchDigest: verification.patchDigest}, digest('8')));
  const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
  assert.equal(contract.reviewId, 'release-1-amendment-a10-multi-bitcoin-split-views');
  assert.equal(contract.tier, 'Full');
  for (const id of ['evidence:topology-drift-negative-control', 'evidence:primary-run',
    'evidence:replay-run', 'evidence:archive', 'attestation:signed-candidate']) assert.ok(contract.requiredInventory.includes(id));
});

test('offline verification rejects insufficient host storage before expensive checks', () => {
  const stats = statfsSync(tmpdir());
  const availableBytes = Number(stats.bavail) * Number(stats.bsize);
  assert.ok(availableBytes < Number.MAX_SAFE_INTEGER);
  assert.equal(hostStoragePreflight(tmpdir(), 0).status, 'passed');
  assert.equal(hostStoragePreflight(tmpdir(), Number.MAX_SAFE_INTEGER).status, 'failed');
});

test('A10 evidence outputs cannot erase source, repository, or adopted private state', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a10-output-'));
  try {
    const input = join(directory, 'input');
    const output = join(directory, 'output');
    assert.equal(validateA10EvidenceOutput(input, output), output);
    for (const unsafe of [input, join(input, 'nested'), directory, repositoryRoot]) {
      assert.throws(() => validateA10EvidenceOutput(input, unsafe), /must be isolated/);
    }
    prepareQualificationOutput(output);
    prepareQualificationOutput(output);
    prepareQualificationOutput(join(directory, 'live'));
    const execution = join(directory, 'live', '.execution');
    mkdirSync(execution);
    assert.throws(() => prepareQualificationOutput(join(directory, 'live')), /\.execution/);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});

test('A10 incident artifacts cannot escape their evidence root', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a10-incident-'));
  try {
    const incident = join(directory, 'incident');
    mkdirSync(incident);
    const manifest = {schemaVersion: 'stacks-attacknet-incident-evidence/v1', errors: [], omissions: [],
      artifacts: [{path: '../outside.json', sha256: digest('1'), bytes: 1}]};
    const path = join(incident, 'manifest.json');
    writeFileSync(path, `${JSON.stringify(manifest)}\n`);
    assert.throws(() => validateA10Incident(path), /invalid/);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});

test('A10 qualification resources pass the production typed CLI decoder', () => {
  const qualification = fileURLToPath(new URL('./qualification/', import.meta.url));
  const primaryPolicy = readFileSync(join(qualification, 'policy-a.yaml'), 'utf8');
  const secondaryPolicy = readFileSync(join(qualification, 'policy-b.yaml'), 'utf8');
  assert.match(primaryPolicy, /bootstrapHeight: 101/);
  assert.match(primaryPolicy, /reserveOutputs: 4/);
  assert.match(primaryPolicy, /epoch-2-05, startHeight: 203/);
  assert.match(primaryPolicy, /epoch-4-0, startHeight: 1000005/);
  const epochTwoFiveHeight = Number(primaryPolicy.match(/epoch-2-5, startHeight: (\d+)/)?.[1]);
  const rewardCycleLength = Number(primaryPolicy.match(/cycleLength: (\d+)/)?.[1]);
  assert.equal(A10_SIGNER_SET_READY_HEIGHT,
    Math.ceil(epochTwoFiveHeight / rewardCycleLength) * rewardCycleLength);
  const epochFourHeight = Number(primaryPolicy.match(/epoch-4-0, startHeight: (\d+)/)?.[1]);
  assert.ok(Number.isSafeInteger(epochFourHeight));
  assert.ok(epochFourHeight % 20 >= 5, 'the parked Epoch 4 height must be outside the five-block PoX prepare phase');
  assert.match(secondaryPolicy, /bootstrapHeight: 0/);
  assert.match(secondaryPolicy, /reserveOutputs: 0/);
  const run = readFileSync(join(qualification, 'run.yaml'), 'utf8');
  assert.match(run, /maxBurnchainFaults: 2/);
  const files = readdirSync(qualification).filter(name => name.endsWith('.yaml')).sort();
  assert.deepEqual(files, ['campaign.yaml', 'network.yaml', 'policy-a.yaml', 'policy-b.yaml', 'run.yaml']);
  for (const file of files) execFileSync('go', ['run', './cmd/attacknet', 'validate', '--file', join(qualification, file),
    '--namespace', 'hacknet-system', '--output', 'json'], {cwd: join(repositoryRoot, 'contrib/helm/hacknet/operator'),
    env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/tmp/attacknet-a10-go-build'}, stdio: 'pipe'});
});

test('A10 qualification parks Epoch 4 until sBTC contract provisioning is supported', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a10-credentials-'));
  try {
    const credentials = JSON.parse(readFileSync(stageQualificationCredentials(directory), 'utf8'));
    const miner = credentials.items.find(item => item.metadata.name === 'a10-miner-config')?.stringData?.['config.toml'];
    assert.equal(typeof miner, 'string');
    assert.match(miner, /epoch_name = "3\.4"/);
    assert.match(miner, /epoch_name = "4\.0"\nstart_height = 1000005/);
    assert.doesNotMatch(miner, /epoch_name = "4\.0"\nstart_height = 245/);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
