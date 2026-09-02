import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  A12_ARTIFACTS, A12_ASSERTIONS, validateA12EgressControl,
  validateA12Campaign, validateA12ForgeryControl, validateA12LiveResult, validateA12Network,
  validateA12NormalImageControl, validateA12Run,
  validateA12ObserverReplacementControl, validateA12PolicyDriftControl,
} from './evidence.mjs';
import {isA12PathPermitted} from './packet.mjs';
import {rewardSetContinuity, stageQualificationInputs} from './qualification/live.mjs';
import {
  A12_ATTESTATION_SCHEMA, A12_CHECK_IDS, A12_PARENT_REVISION,
  A12_VERIFICATION_SCHEMA, validateA12CandidateAttestation, validateA12Verification,
} from './verify.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, '../../../../..');
const tree = 'a'.repeat(40);
const sha = character => `sha256:${character.repeat(64)}`;
const now = '2026-08-30T00:00:00.000Z';

test('A12 packet scope includes its binary-patch attribute contract', () => {
  assert.equal(isA12PathPermitted('.gitattributes'), true);
  assert.equal(isA12PathPermitted('contrib/attacknet/test/example'), true);
  assert.equal(isA12PathPermitted('contrib/helm/hacknet/example'), true);
  assert.equal(isA12PathPermitted('.gitconfig'), false);
});

test('A12 Full-tier contract binds every live evidence class', () => {
  const contract = JSON.parse(readFileSync(resolve(directory, 'contract.json'), 'utf8'));
  assert.equal(contract.reviewId, 'release-1-amendment-a12-deterministic-adversarial-actors');
  assert.equal(contract.tier, 'Full');
  assert.equal(contract.requirements.length, 12);
  for (const id of [
    'evidence:normal-image-control', 'evidence:policy-drift-control', 'evidence:egress-control',
    'evidence:forgery-control', 'evidence:observer-replacement-control',
    'evidence:below-quorum-run', 'evidence:quorum-loss-run', 'evidence:replay-run',
    'evidence:archive', 'attestation:signed-candidate',
  ]) assert.ok(contract.requiredInventory.includes(id), `contract omits ${id}`);
  assert.equal(Object.keys(A12_ARTIFACTS).length, 22);
  assert.equal(A12_ASSERTIONS.length, 10);
});

test('normal image and policy drift controls require zero cluster mutations', () => {
  const normal = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-normal-image-control/v1',
    outcome: 'Passed', classification: 'ProbeBaselineUnavailable', campaignAdmitted: false,
    clusterMutationsBefore: 5, clusterMutationsAfter: 5,
    signerSetContinuity: {ready: true, cycle: 11, nextCycle: 12, burnHeight: 240,
      blocksUntilNextCycle: 20, currentSignerCount: 3, nextSignerCount: 3,
      currentDigest: sha('a'), nextDigest: sha('a')},
  };
  assert.doesNotThrow(() => validateA12NormalImageControl(normal, tree));
  assert.throws(() => validateA12NormalImageControl({...normal, clusterMutationsAfter: 6}, tree), /before mutation/);
  const drift = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-policy-drift-control/v1',
    outcome: 'Passed', classification: 'AdmissionInputChanged', clusterMutationsBefore: 0,
    clusterMutationsAfter: 0, admittedInventoryDigest: sha('1'), changedInventoryDigest: sha('2'),
    restoredInventoryDigest: sha('3'), admittedPolicyDigest: sha('4'), changedPolicyDigest: sha('5'),
    restoredPolicyDigest: sha('4'),
  };
  assert.doesNotThrow(() => validateA12PolicyDriftControl(drift, tree));
  assert.throws(() => validateA12PolicyDriftControl({...drift, restoredPolicyDigest: sha('6')}, tree), /identity barrier/);
});

test('egress contract proves allowed dependencies and both forbidden surfaces', () => {
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-egress-control/v1',
    outcome: 'Passed', profile: 'restricted', networkPolicySpecDigest: sha('3'), checks: {
      dns: {allowed: true}, declaredDependency: {allowed: true},
      kubernetesAPI: {allowed: false}, undeclaredActor: {allowed: false},
    },
  };
  assert.doesNotThrow(() => validateA12EgressControl(value, tree));
  value.checks.kubernetesAPI.allowed = true;
  assert.throws(() => validateA12EgressControl(value, tree), /allowlist/);
});

test('forgery and observer replacement controls cannot report Passed evidence', () => {
  const forgery = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-forgery-control/v1',
    outcome: 'Passed', classification: 'SignatureVerificationFailed', accepted: false,
    terminalPassPossible: false,
  };
  assert.doesNotThrow(() => validateA12ForgeryControl(forgery, tree));
  assert.throws(() => validateA12ForgeryControl({...forgery, accepted: true}, tree), /substitution/);
  const replacement = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-observer-replacement-control/v1',
    outcome: 'Passed', classification: 'TargetIdentityDiverged', beforePodUID: 'old',
    afterPodUID: 'new', campaignPhase: 'Failed',
  };
  assert.doesNotThrow(() => validateA12ObserverReplacementControl(replacement, tree));
  assert.throws(() => validateA12ObserverReplacementControl({...replacement, campaignPhase: 'Passed'}, tree), /stale attribution/);
});

test('aggregate live result binds healthy degradation, quorum loss, and replay', () => {
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-live-qualification/v1',
    outcome: 'Passed', architecture: 'arm64', kindNodes: ['control-plane', 'worker', 'worker2'],
    capturedAt: now,
    belowQuorum: {runPhase: 'Passed', duringOutcome: 'Proven', outcomeClass: 'bounded-progress', policyMatchDelta: 2},
    quorumLoss: {runPhase: 'Failed', duringOutcome: 'Violated', outcomeClass: 'required-progress-absent'},
    replay: {outcomeClass: 'bounded-progress', policyMatchDelta: 2},
    rewardSetContinuity: Object.fromEntries(['primary', 'replay'].map(name => [name, {
      ready: true, cycle: 11, nextCycle: 12, currentSignerCount: 3, nextSignerCount: 3,
      burnHeight: 296, blocksUntilNextCycle: 4,
      currentDigest: sha('a'), nextDigest: sha('a'),
    }])),
    artifactDigests: Object.fromEntries(Array.from({length: 8}, (_, index) => [`artifact-${index}`, sha(String(index + 1))])),
  };
  assert.doesNotThrow(() => validateA12LiveResult(value, tree));
  assert.throws(() => validateA12LiveResult({...value, replay: {...value.replay, policyMatchDelta: 1}}, tree), /replay/);
});

test('reward-set continuity requires the same canonical identities and weights across a boundary', () => {
  const signers = [
    {signing_key: `03${'b'.repeat(64)}`, weight: 3},
    {signing_key: `02${'a'.repeat(64)}`, weight: 1},
    {signing_key: `03${'c'.repeat(64)}`, weight: 4},
  ];
  const pox = {current_cycle: {id: 11}, next_cycle: {id: 12}, current_burnchain_block_height: 296, next_reward_cycle_in: 4};
  const receipt = rewardSetContinuity(pox, {stacker_set: {signers}}, {stacker_set: {signers: [...signers].reverse()}});
  assert.equal(receipt.ready, true);
  assert.equal(receipt.currentDigest, receipt.nextDigest);
  const changed = structuredClone(signers);
  changed[0].weight++;
  assert.equal(rewardSetContinuity(pox, {stacker_set: {signers}}, {stacker_set: {signers: changed}}).ready, false);
  assert.equal(rewardSetContinuity({...pox, next_cycle: {id: 13}}, {stacker_set: {signers}}, {stacker_set: {signers}}).ready, false);
});

test('verification and final attestation are qualified-tree and summary bound', () => {
  assert.ok(A12_CHECK_IDS.includes('patched-signer-rust-tests'));
  const checks = A12_CHECK_IDS.map((id, index) => ({
    id, status: 'passed', command: `check-${index}`, durationMs: index + 1,
    startedAt: now, exitCode: 0, outputDigest: sha(String((index % 9) + 1)), stdout: '', stderr: '',
  }));
  const verification = {
    schema: A12_VERIFICATION_SCHEMA, qualifiedTree: tree, parentRevision: A12_PARENT_REVISION,
    patchDigest: sha('a'), outcome: 'Passed', recordedAt: now, checks,
  };
  assert.doesNotThrow(() => validateA12Verification(verification, tree));
  assert.throws(() => validateA12Verification({...verification, checks: checks.slice(1)}, tree), /duplicate, missing, or unknown/);
  const attestation = {
    schema: A12_ATTESTATION_SCHEMA, candidateRevision: 'b'.repeat(40), candidateTree: tree,
    parentRevision: A12_PARENT_REVISION, patchDigest: sha('a'), evidenceSummaryDigest: sha('b'),
    signatureVerified: true, recordedAt: now,
  };
  assert.doesNotThrow(() => validateA12CandidateAttestation(attestation, {
    qualifiedTree: tree, patchDigest: sha('a'),
  }, sha('b')));
  assert.throws(() => validateA12CandidateAttestation({...attestation, candidateTree: 'c'.repeat(40)}, {
    qualifiedTree: tree, patchDigest: sha('a'),
  }, sha('b')), /invalid/);
});

function snapshot(kind, name, resource) {
  return {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status', resourceDigest: sha('9'),
    resource: {apiVersion: 'testing.stacks.org/v1beta1', kind, metadata: {name, uid: `${name}-uid`, generation: 1}, ...resource},
  };
}

test('network, campaign, and run evidence validators bind distinct identities and outcomes', () => {
  const actors = [];
  for (const signer of ['signer-1', 'signer-2', 'signer-3']) {
    actors.push({name: signer, identityReady: true, adversarialPolicyDigest: sha('a'),
      adversarialEgressProfile: 'restricted', egressPolicyDigest: sha('b')});
    actors.push({name: `${signer}-observer`, identityReady: true, adversarialPolicyDigest: sha('a'),
      adversarialEgressProfile: 'restricted', egressPolicyDigest: sha('c')});
  }
  const network = snapshot('StacksNetwork', 'a12-adversarial', {status: {
    phase: 'Ready', inventoryReady: true, observedGeneration: 1, inventoryDigest: sha('d'), actors,
  }});
  assert.doesNotThrow(() => validateA12Network(network, tree, 'a12-adversarial'));
  const reports = {};
  for (const phase of ['before', 'during', 'after']) reports[`stage/action/${phase}/signer-1SignedJson`] = JSON.stringify({
    nonce: `${phase}-0123456789abcdef`,
    attestation: {keyId: sha('e'), signature: 'signed'},
    observedAt: now,
  });
  const campaign = snapshot('FaultCampaign', 'campaign', {status: {
    phase: 'Passed', admission: {signerSetDigest: sha('f')}, probeArtifacts: reports,
    stages: [{actions: [{effectResults: [{actor: 'signer-1', outcome: 'Proven', policyMatches: 2,
      reportDigest: sha('1')}], recoveryResults: [{actor: 'signer-1', outcome: 'Proven'}]}]}],
  }});
  assert.doesNotThrow(() => validateA12Campaign(campaign, tree, ['signer-1']));
  const repeatedNonce = structuredClone(campaign);
  const duplicate = JSON.parse(repeatedNonce.resource.status.probeArtifacts['stage/action/before/signer-1SignedJson']).nonce;
  for (const key of Object.keys(repeatedNonce.resource.status.probeArtifacts)) {
    const report = JSON.parse(repeatedNonce.resource.status.probeArtifacts[key]);
    report.nonce = duplicate;
    repeatedNonce.resource.status.probeArtifacts[key] = JSON.stringify(report);
  }
  assert.throws(() => validateA12Campaign(repeatedNonce, tree, ['signer-1']), /nonce-distinct/);
  const run = snapshot('AttacknetRun', 'run', {
    spec: {networkRef: 'a12-adversarial'}, status: {phase: 'Failed', resolvedCampaigns: [{}],
      scheduleSummary: {networkInventory: {digest: sha('2')}, signerSetDigest: sha('3')},
      protocolAssertions: {during: {outcome: 'Violated', results: [{reason: 'RequiredProgressAbsent'}]}},
    },
  });
  assert.doesNotThrow(() => validateA12Run(run, tree, 'a12-adversarial', 'Failed', 'Violated'));
  run.resource.status.protocolAssertions.during.results = [];
  assert.throws(() => validateA12Run(run, tree, 'a12-adversarial', 'Failed', 'Violated'), /no-progress/);
});

test('A12 qualification resources pass the production typed CLI decoder', () => {
  const qualification = resolve(directory, 'qualification');
  const files = readdirSync(qualification).filter(name => name.endsWith('.yaml')).sort();
  assert.deepEqual(files, [
    'below-quorum-campaign.yaml', 'below-quorum-run.yaml', 'network.yaml', 'policy.yaml',
    'quorum-loss-campaign.yaml', 'quorum-loss-run.yaml',
  ]);
  for (const file of files) {
    execFileSync('go', ['run', './cmd/attacknet', 'validate', '--file', join(qualification, file),
      '--namespace', 'hacknet-system', '--output', 'json'], {
      cwd: join(repositoryRoot, 'contrib/helm/hacknet/operator'),
      env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/tmp/r1a12-go-cache'}, stdio: 'pipe',
    });
  }
});

test('quorum-loss evidence preserves one independently attributable action per signer', () => {
  const reports = {};
  const actions = [];
  for (const [index, actor] of ['signer-2', 'signer-3'].entries()) {
    for (const phase of ['before', 'during', 'after']) {
      reports[`stage/${actor}/${phase}/${actor}SignedJson`] = JSON.stringify({
        nonce: `${actor}-${phase}-0123456789abcdef`, observedAt: now,
        attestation: {keyId: sha(String(index + 1)), signature: 'signed'},
      });
    }
    actions.push({
      effectResults: [{actor, outcome: 'Proven', policyMatches: index + 1, reportDigest: sha('3')}],
      recoveryResults: [{actor, outcome: 'Proven'}],
    });
  }
  const campaign = snapshot('FaultCampaign', 'quorum-loss', {status: {
    phase: 'Passed', admission: {signerSetDigest: sha('4')}, probeArtifacts: reports,
    stages: [{actions}],
  }});
  assert.doesNotThrow(() => validateA12Campaign(campaign, tree, ['signer-2', 'signer-3']));
  const grouped = structuredClone(campaign);
  grouped.resource.status.stages[0].actions = [{
    effectResults: actions.flatMap(action => action.effectResults),
    recoveryResults: actions.flatMap(action => action.recoveryResults),
  }];
  assert.throws(() => validateA12Campaign(grouped, tree, ['signer-2', 'signer-3']), /independently attributable/);
});

test('qualification input staging derives three independent signer secrets and corrected miner config', () => {
  const root = mkdtempSync(resolve(tmpdir(), 'a12-inputs-'));
  try {
    const staged = stageQualificationInputs(root);
    const list = JSON.parse(readFileSync(staged.path, 'utf8'));
    assert.deepEqual(list.items.map(item => item.metadata.name), [
      'a12-miner-config', 'a12-signer-1', 'a12-signer-2', 'a12-signer-3', 'a12-stacker-credentials',
    ]);
    const miner = list.items[0].stringData['config.toml'];
    assert.ok(miner.includes('start_height = 1000005'));
    assert.ok(!miner.includes('${SERVICE:follower-2}'));
    assert.equal(new Set(list.items.slice(1, 4).map(item => item.stringData['signer.toml'])).size, 3);
  } finally { rmSync(root, {recursive: true, force: true}); }
});
