import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  A9_STORAGE_MINIMUM_AVAILABLE_BYTES, validateA9AttacknetCheck, validateA9Campaign,
  validateA9Flash, validateA9HacknetCheck, validateA9Incident, validateA9NegativeControl,
  validateA9Run, validateA9StoragePreflight, validateA9Views, portableArchiveEnvironment,
} from './evidence.mjs';
import {
  A9_BUILD_PURPOSES, A9_INSTALLED_PURPOSES, a9RuntimeImageIDs,
  validateA9CandidateBuild,
} from './qualification/candidate-build.mjs';
import {
  runIsObservableTerminal, stageQualificationCredentials, stageQualificationManifests,
} from './qualification/live.mjs';
import {
  A9_ATTESTATION_SCHEMA, A9_CHECK_IDS, A9_VERIFICATION_SCHEMA,
  validateA9CandidateAttestation, validateA9Verification,
} from './verify.mjs';

const tree = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const observedAt = '2026-08-27T00:00:00.000Z';
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..');

test('A9 archive creation disables macOS metadata members', () => {
  assert.equal(portableArchiveEnvironment({PATH: '/bin'}).COPYFILE_DISABLE, '1');
  assert.equal(portableArchiveEnvironment({PATH: '/bin'}).PATH, '/bin');
});

function snapshot(kind, resource) {
  return {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status', resourceDigest: digest('1'),
    resource: {apiVersion: 'testing.stacks.org/v1beta1', kind, ...resource},
  };
}

function header(height, character, previous) {
  return {hash: character.repeat(64), height, previousblockhash: previous?.repeat(64), chainwork: height.toString(16)};
}

function campaign(network = 'a9-qualification') {
  const original = {chain: 'regtest', blocks: 210, bestblockhash: '2'.repeat(64), chainwork: 'd2'};
  const final = {chain: 'regtest', blocks: 211, bestblockhash: '5'.repeat(64), chainwork: 'd3'};
  const result = {
    schemaVersion: 'attacknet-burnchain-reorg-result/v1', preparedDigest: digest('2'),
    original, forkParent: header(208, '0', 'f'),
    originalBranch: [header(209, '1', '0'), header(210, '2', '1')],
    replacementBranch: [header(209, '3', '0'), header(210, '4', '3'), header(211, '5', '4')],
    final, finalTips: [], canonicalProven: true,
    receipts: [
      {sequence: 1, method: 'invalidateblock', outcome: 'acknowledged'},
      {sequence: 2, method: 'generatetoaddress', outcome: 'acknowledged'},
      {sequence: 3, method: 'generatetoaddress', outcome: 'acknowledged'},
      {sequence: 4, method: 'generatetoaddress', outcome: 'acknowledged'},
      {sequence: 5, method: 'reconsiderblock', outcome: 'acknowledged'},
    ],
  };
  return snapshot('FaultCampaign', {
    metadata: {name: `${network}-campaign`, uid: `${network}-campaign-uid`}, spec: {networkRef: network},
    status: {phase: 'Passed', admission: {networkUid: `${network}-uid`,
      networkInventory: {digest: digest('9')}}, cleanup: {allRecovered: true}, stages: [{
      id: 'replace-tip', actions: [{
        id: 'replace', phase: 'Completed', mutation: {kind: 'BurnchainReorgWorker'},
        actualInjection: {preparedDigest: result.preparedDigest},
        effectResults: [{assertion: 'BurnchainReorgProven', outcome: 'Proven', evidence: result}],
        recoveryResults: [{assertion: 'BurnchainPolicyRestored', outcome: 'Proven'}],
      }],
    }]},
  });
}

function result(id) { return {id, outcome: 'Proven'}; }
function run(network = 'a9-qualification') {
  const assertion = name => ({outcome: 'Proven', results: [result(name)]});
  return snapshot('AttacknetRun', {
    metadata: {name: `${network}-run`, uid: `${network}-run-uid`},
    spec: {networkRef: network, seed: 'same-seed'},
    status: {phase: 'Passed', cleanup: {completed: true}, budgetUsage: {burnchainFaults: 1},
      scheduleSummary: {digest: digest('3')}, protocolAssertions: {
        baseline: assertion('baseline'), during: assertion('during'), recovery: assertion('recovery'),
      }},
  });
}

function views(network = 'a9-qualification') {
  return {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a9-node-views/v1',
    network: {name: network, uid: `${network}-uid`, inventoryDigest: digest('4')},
    replacementTip: '5'.repeat(64), replacementHeader: {hash: '5'.repeat(64), confirmations: 2},
    bitcoin: {blocks: 211, bestblockhash: '6'.repeat(64)}, observations: [
      'miner-1', 'signer-node-1', 'follower-1',
    ].map(actor => ({actor, podUID: `${actor}-uid`, runtimeImageID: digest('5'),
      burnBlockHeight: 211, stacksTipHeight: 30, evidenceClass: 'actor_self_reported'})),
  };
}

test('campaign validator requires an exact higher-work two-for-three branch proof', () => {
  assert.doesNotThrow(() => validateA9Campaign(campaign(), tree, 'a9-qualification'));
  const corrupt = structuredClone(campaign());
  corrupt.resource.status.stages[0].actions[0].effectResults[0].evidence.replacementBranch.pop();
  assert.throws(() => validateA9Campaign(corrupt, tree, 'a9-qualification'), /two-for-three/);

  const unlinked = structuredClone(campaign());
  unlinked.resource.status.stages[0].actions[0].effectResults[0].evidence.replacementBranch[1].previousblockhash = 'f'.repeat(64);
  assert.throws(() => validateA9Campaign(unlinked, tree, 'a9-qualification'), /two-for-three/);
});

test('campaign validator requires the production Completed action lifecycle phase', () => {
  const value = campaign();
  value.resource.status.stages[0].actions[0].phase = 'Recovered';
  assert.throws(() => validateA9Campaign(value, tree, 'a9-qualification'), /two-for-three/);
});

test('campaign validator requires an immutable admitted network identity', () => {
  const missingUID = campaign();
  delete missingUID.resource.status.admission.networkUid;
  assert.throws(() => validateA9Campaign(missingUID, tree, 'a9-qualification'), /two-for-three/);
  const missingInventory = campaign();
  delete missingInventory.resource.status.admission.networkInventory;
  assert.throws(() => validateA9Campaign(missingInventory, tree, 'a9-qualification'), /two-for-three/);
});

test('incident validator accepts omitted empty error lists but rejects reported errors', t => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a9-incident-test-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  writeFileSync(join(directory, 'artifact.txt'), '');
  const manifest = {schemaVersion: 'stacks-attacknet-incident-evidence/v1', artifacts: [{
    path: 'artifact.txt', bytes: 0,
    sha256: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  }]};
  const path = join(directory, 'manifest.json');
  writeFileSync(path, `${JSON.stringify(manifest)}\n`);
  assert.doesNotThrow(() => validateA9Incident(path));
  manifest.errors = ['capture failed'];
  writeFileSync(path, `${JSON.stringify(manifest)}\n`);
  assert.throws(() => validateA9Incident(path), /incomplete/);
});

test('live qualification diagnoses failed runs without weakening Passed cleanup proof', () => {
  const value = {metadata: {generation: 2}, status: {observedGeneration: 2}};
  for (const phase of ['Failed', 'Inconclusive', 'Paused']) {
    value.status.phase = phase;
    delete value.status.cleanup;
    assert.equal(runIsObservableTerminal(value), true);
  }
  value.status.phase = 'Passed';
  assert.equal(runIsObservableTerminal(value), false);
  value.status.cleanup = {completed: true};
  assert.equal(runIsObservableTerminal(value), true);
});

test('negative control rejects any mutation receipt', () => {
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a9-stale-precondition/v1',
    outcome: 'Passed', observedAt, workerPodUID: 'worker-uid',
    before: {blocks: 210, bestblockhash: '2'.repeat(64)},
    intervening: {blocks: 211, bestblockhash: '6'.repeat(64)},
    after: {blocks: 211, bestblockhash: '6'.repeat(64)},
    workerStatus: {phase: 'Failed', failure: 'approved Bitcoin precondition is stale', result: {
      original: {bestblockhash: '2'.repeat(64)}, receipts: [], canonicalProven: false,
    }},
  };
  assert.doesNotThrow(() => validateA9NegativeControl(value, tree));
  value.workerStatus.result.receipts.push({method: 'invalidateblock'});
  assert.throws(() => validateA9NegativeControl(value, tree), /zero reorg mutation/);
});

test('run and actor-view validators require independently proven recovery', () => {
  assert.doesNotThrow(() => validateA9Run(run(), tree, 'a9-qualification'));
  assert.doesNotThrow(() => validateA9Views(views(), tree, 'a9-qualification', '5'.repeat(64)));
  const broken = structuredClone(run());
  broken.resource.status.protocolAssertions.recovery.results[0].outcome = 'Violated';
  assert.throws(() => validateA9Run(broken, tree, 'a9-qualification'), /not all proven/);
});

test('flash validator requires restored policy, exact receipt, and three converged views', () => {
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a9-flash-receipt/v1',
    flash: {id: 'a9-after-reorg-flash', blocks: 5, interval: '1s'},
    policyBefore: {spec: {paused: false}, status: {observedHeight: 211}},
    policyAfter: {status: {phase: 'Ready', appliedFlashId: 'a9-after-reorg-flash', observedHeight: 216}},
    actorViews: {observations: ['miner', 'node', 'follower'].map(actor => ({actor, burnBlockHeight: 216}))},
  };
  assert.doesNotThrow(() => validateA9Flash(value, tree));
  value.policyAfter.status.appliedFlashId = 'wrong';
  assert.throws(() => validateA9Flash(value, tree), /bounded flash/);
});

test('storage preflight proves root and image capacity at both deployment boundaries', () => {
  const node = name => ({name, ok: true,
    rootFilesystem: {availableBytes: A9_STORAGE_MINIMUM_AVAILABLE_BYTES},
    imageFilesystem: {availableBytes: A9_STORAGE_MINIMUM_AVAILABLE_BYTES}});
  const check = phase => ({phase, exitCode: 0, schemaVersion: 1, ok: true,
    observedAt, source: 'kubelet-stats-summary',
    minimumAvailableBytes: A9_STORAGE_MINIMUM_AVAILABLE_BYTES,
    nodes: ['control-plane', 'worker', 'worker2'].map(node)});
  const value = {schemaVersion: 'stacks-attacknet-a9-storage-preflight/v1',
    qualifiedTree: tree, minimumAvailableBytes: A9_STORAGE_MINIMUM_AVAILABLE_BYTES,
    recordedAt: observedAt, checks: [check('before-build'), check('before-network')]};
  assert.doesNotThrow(() => validateA9StoragePreflight(value, tree));
  value.checks[1].nodes[2].imageFilesystem.availableBytes = 0;
  assert.throws(() => validateA9StoragePreflight(value, tree), /before-network/);
});

test('whole-product results are exact-tree complete passes', () => {
  const attacknet = {schemaVersion: 'stacks-attacknet-offline-check-result/v1',
    sourceRevision: tree, status: 'passed', suites: [
      {name: 'contract', tests: 2, passed: 2, failed: 0},
    ]};
  const hacknet = {schemaVersion: 'stacks-hacknet-offline-check-result/v1',
    sourceRevision: tree, status: 'passed', requiredChecks: ['controller'],
    optionalChecks: ['go', 'envtest', 'helm'].map(name => ({name, status: 'passed'}))};
  assert.doesNotThrow(() => validateA9AttacknetCheck(attacknet, tree));
  assert.doesNotThrow(() => validateA9HacknetCheck(hacknet, tree));
  attacknet.suites[0].failed = 1;
  assert.throws(() => validateA9AttacknetCheck(attacknet, tree), /complete/);
  hacknet.optionalChecks[1].status = 'skipped-unavailable';
  hacknet.optionalChecks[1].reason = 'missing assets';
  assert.throws(() => validateA9HacknetCheck(hacknet, tree), /envtest/);
});

function kindLoad(refs) {
  const nodes = ['kind-control-plane', 'kind-worker', 'kind-worker2'];
  return {schemaVersion: 'stacks-attacknet-kind-image-load/v1', outcome: 'Loaded',
    nodes: nodes.map(name => ({name, architecture: 'arm64'})),
    images: nodes.flatMap(node => refs.map((requestedRef, index) => ({
      node, requestedRef, runtimeImageID: digest(String((index % 9) + 1)), verified: true,
    }))),
  };
}

test('candidate build binds every image to all three arm64 kind nodes', () => {
  const buildImages = A9_BUILD_PURPOSES.map((purpose, index) => ({purpose, ref: `local/${purpose}:a9`, id: digest(String((index % 9) + 1))}));
  const installImages = A9_INSTALLED_PURPOSES.map(purpose => {
    const built = buildImages.find(image => image.purpose === purpose);
    return {purpose, deploymentRef: built.ref, id: built.id};
  });
  const actorImages = ['stacks-core', 'stacker'].map(purpose => {
    const built = buildImages.find(image => image.purpose === purpose);
    return {purpose, ref: built.ref, immutableID: built.id};
  });
  const value = {schemaVersion: 'stacks-attacknet-a9-candidate-build/v1', qualifiedTree: tree,
    capturedAt: observedAt, build: {schemaVersion: 'stacks-attacknet-local-build/v1', images: buildImages},
    install: {schemaVersion: 'stacks-attacknet-local-install/v1', images: installImages,
      kindImageLoad: kindLoad(installImages.map(image => image.deploymentRef))},
    actorImages, actorImageLoad: kindLoad(actorImages.map(image => image.ref)),
    runOperatorImageID: buildImages.find(image => image.purpose === 'run-operator').id};
  assert.doesNotThrow(() => validateA9CandidateBuild(value, tree));
  assert.equal(a9RuntimeImageIDs(value, tree).size, A9_BUILD_PURPOSES.length);
  value.actorImageLoad.images.pop();
  assert.throws(() => validateA9CandidateBuild(value, tree), /incomplete/);
});

test('verification and post-sign attestation are exact-tree contracts', () => {
  const verification = {schema: A9_VERIFICATION_SCHEMA, qualifiedTree: tree,
    parentRevision: 'ec281465b526caf690f97e2d026132f149e5b965', patchDigest: digest('6'),
    outcome: 'Passed', recordedAt: observedAt, checks: A9_CHECK_IDS.map(id => ({id,
      status: 'passed', command: id, cwd: '.', startedAt: observedAt, durationMs: 1,
      exitCode: 0, outputDigest: digest('7'), stdout: '', stderr: ''}))};
  assert.doesNotThrow(() => validateA9Verification(verification, tree));
  const attestation = {schema: A9_ATTESTATION_SCHEMA, candidateRevision: 'b'.repeat(40),
    candidateTree: tree, parentRevision: verification.parentRevision,
    patchDigest: verification.patchDigest, evidenceSummaryDigest: digest('8'),
    signatureVerified: true, recordedAt: observedAt};
  assert.doesNotThrow(() => validateA9CandidateAttestation(attestation, {qualifiedTree: tree,
    patchDigest: verification.patchDigest}, digest('8')));
});

test('A9 contract enumerates every live proof and review identity', () => {
  const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
  assert.equal(contract.reviewId, 'release-1-amendment-a9-bitcoin-reorganizations');
  assert.equal(contract.tier, 'Full');
  for (const id of ['evidence:negative-control', 'evidence:primary-campaign',
    'evidence:flash-receipt', 'evidence:replay-campaign', 'evidence:storage-preflight',
    'attestation:signed-candidate']) {
    assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
  }
});

test('A9 qualification resources pass the production typed CLI decoder', () => {
  const qualification = fileURLToPath(new URL('./qualification/', import.meta.url));
  const files = readdirSync(qualification).filter(name => name.endsWith('.yaml')).sort();
  assert.deepEqual(files, [
    'network-replay.yaml', 'network.yaml', 'policy-replay.yaml', 'policy.yaml',
    'reorg-template.yaml', 'run-replay.yaml', 'run.yaml',
  ]);
  for (const file of files) {
    execFileSync('git', ['ls-files', '--error-unmatch', join(qualification, file)], {
      cwd: repositoryRoot, stdio: 'pipe',
    });
  }
  for (const file of files) {
    execFileSync('go', [
      'run', './cmd/attacknet', 'validate', '--file', join(qualification, file),
      '--namespace', 'hacknet-system', '--output', 'json',
    ], {cwd: join(repositoryRoot, 'contrib/helm/hacknet/operator'), stdio: 'pipe'});
  }
});

test('A9 qualification snapshots manifests under its explicit execution root', t => {
  const execution = mkdtempSync(join(tmpdir(), 'attacknet-a9-execution-test-'));
  t.after(() => rmSync(execution, {recursive: true, force: true}));
  const manifestDirectory = stageQualificationManifests(execution);
  const files = readdirSync(manifestDirectory).sort();
  assert.deepEqual(files, [
    'network-replay.yaml', 'network.yaml', 'policy-replay.yaml', 'policy.yaml',
    'reorg-template.yaml', 'run-replay.yaml', 'run.yaml',
  ]);
  assert.equal(readFileSync(join(manifestDirectory, 'reorg-template.yaml'), 'utf8'),
    readFileSync(new URL('./qualification/reorg-template.yaml', import.meta.url), 'utf8'));
  const credentials = JSON.parse(readFileSync(stageQualificationCredentials(execution), 'utf8'));
  assert.equal(credentials.kind, 'List');
  assert.deepEqual(credentials.items.map(item => item.metadata.name), [
    'a9-miner-config', 'a9-signer-config', 'a9-stacker-credentials',
  ]);
  assert.ok(credentials.items.every(item => item.kind === 'Secret'));
});
