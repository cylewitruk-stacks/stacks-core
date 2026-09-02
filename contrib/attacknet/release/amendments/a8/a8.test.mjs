import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import test from 'node:test';
import {gzipSync} from 'node:zlib';

import {
  A8_ARTIFACTS, A8_ASSERTIONS, A8_SUMMARY_SCHEMA, assembleA8Evidence, validateA8BaselineRun,
  validateA8LokiIngressControl, validateA8SourceLossControl, validateA8SourceLossRun, validateA8StacksTriggerRun, validateA8TeardownFailure,
  validateA8Teardown, validateA8ViolationRun,
} from './evidence.mjs';
import {buildA8Packet} from './packet.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {
  A8_BUILD_PURPOSES, A8_INSTALLED_PURPOSES, candidateRuntimeImageIDs,
  validateCandidateBuildReceipt,
} from './qualification/candidate-build.mjs';
import {
  candidateContainerIdentity, observesActiveFaultCampaign, prepareQualificationOutput,
} from './qualification/live.mjs';
import {isMainModule, isMaterializedSource, materializeQualifiedTree} from './qualified-source.mjs';
import {
  A8_CANDIDATE_ATTESTATION_SCHEMA, A8_CHECK_IDS, A8_VERIFICATION_SCHEMA,
  validateA8CandidateAttestation, validateA8Verification,
} from './verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
const repositoryRoot = resolve(dirname(new URL(import.meta.url).pathname), '../../../../..');
const candidateRevision = 'a'.repeat(40);
const qualifiedTree = 'b'.repeat(40);
const parentRevision = 'c428fcbb42bb8884cc1fe47055576130ba061346';
const immutable = character => `sha256:${character.repeat(64)}`;
const observedAt = '2026-08-26T00:00:00.000Z';

function verification() {
  return {
    schema: A8_VERIFICATION_SCHEMA,
    qualifiedTree,
    parentRevision,
    patchDigest: `sha256:${bytesDigest(Buffer.from('A8 candidate patch\n'))}`,
    outcome: 'Passed',
    recordedAt: observedAt,
    checks: A8_CHECK_IDS.map(id => ({
      id, status: 'passed', command: id, cwd: '.', startedAt: observedAt,
      durationMs: 1, exitCode: 0, outputDigest: immutable('1'), stdout: '', stderr: '',
    })),
  };
}

function source(actor = 'node-1') {
  return {
    actor, role: actor.startsWith('signer') ? 'signer' : 'follower',
    podName: `${actor}-0`, podUID: `${actor}-uid`, runtimeImageID: immutable('2'),
    serviceName: actor, observedAt, evidenceClass: 'actor_self_reported',
  };
}

function result(id, outcome) {
  return {
    id, type: 'TelemetryCompleteness', outcome,
    reason: outcome === 'Proven' ? 'AssertionSatisfied'
      : outcome === 'Violated' ? 'AssertionViolated' : 'EvidenceDeadlineExceeded',
    evidence: {
      networkUID: 'network-uid', inventoryDigest: immutable('3'), observedAt,
      current: {'node-1': 1}, sources: [source()],
    },
  };
}

function runSnapshot(name, phase, protocolAssertions, extraStatus = {}) {
  return {
    qualifiedTree,
    schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status',
    resourceDigest: immutable('4'),
    resource: {
      apiVersion: 'testing.stacks.org/v1beta1', kind: 'AttacknetRun',
      metadata: {
        name, namespace: 'hacknet-system', uid: `${name}-uid`, generation: 1, resourceVersion: '42',
      },
      spec: {networkRef: 'attacknet'},
      status: {phase, protocolAssertions, ...extraStatus},
    },
  };
}

function sourceLossControl() {
  return {
    schemaVersion: 'stacks-attacknet-a8-source-loss-control/v1',
    control: 'topology-paused-service-withdrawal', actor: 'follower-1',
    faultOracle: {
      childCampaign: 'a8-source-loss-execution-source-loss', childUID: 'child-uid',
      phase: 'Running', activeObservedAt: observedAt,
    },
    topology: {
      deployment: 'hacknet', deploymentUID: 'deployment-uid', originalReplicas: 1,
      pausedAt: observedAt, restoredReplicas: 1, restoredAt: observedAt,
    },
    service: {
      name: 'a8-qualification-follower-1', beforeUID: 'service-before',
      deletedAt: observedAt, restoredUID: 'service-after', restoredAt: observedAt,
    },
    network: {
      before: {uid: 'network-uid', inventoryDigest: immutable('3')},
      after: {uid: 'network-uid', inventoryDigest: immutable('3')},
    },
    run: {name: 'source-loss', uid: 'source-loss-uid', generation: 1, resourceVersion: '42'},
    runPhase: 'Inconclusive', runCompletedAt: observedAt,
  };
}

function lokiIngressControl() {
  return {
    schemaVersion: 'stacks-attacknet-a8-loki-ingress-control/v1',
    service: 'a8-qualification-attacknet-loki', networkPolicy: 'a8-qualification-attacknet-loki-ingress',
    observedAt, outcomes: [
      {name: 'a8-loki-policy-allowed', podUID: 'allowed-uid', expectedReachable: true, phase: 'Succeeded', exitCode: 0},
      {name: 'a8-loki-policy-denied', podUID: 'denied-uid', expectedReachable: false, phase: 'Succeeded', exitCode: 0},
    ],
  };
}

function values(root) {
  const baseline = runSnapshot('baseline', 'Passed', {
    baseline: {outcome: 'Proven', results: [result('baseline', 'Proven')]},
    recovery: {outcome: 'Proven', results: [result('recovery', 'Proven')]},
  });
  const violation = runSnapshot('violation', 'Failed', {
    during: {outcome: 'Violated', results: [result('during', 'Violated')]},
  }, {attribution: 'ProtocolAssertion'});
  const sourceLoss = runSnapshot('source-loss', 'Inconclusive', {
    during: {outcome: 'Inconclusive', results: [result('during', 'Inconclusive')]},
  });
  const stacksTrigger = runSnapshot('stacks-trigger', 'Passed', {}, {
    triggerReceipts: [{
      schemaVersion: 'stacks-attacknet-trigger-receipt/v1', subject: 'fault', trigger: 'StacksHeight',
      evidence: [{kind: 'StacksHeight', targetHeight: 10, observedHeight: 12, observedAt,
        source: {kind: 'ProtocolObservation', name: 'network-uid', uid: immutable('3'), trusted: true}}],
    }],
  });
  const lokiRaw = Buffer.from(`${JSON.stringify({
    timestampNs: '1', labels: {attacknet_network: 'attacknet', attacknet_actor: 'follower-1'}, line: 'ready',
  })}\n`);
  const lokiLogs = gzipSync(lokiRaw);
  const lokiSource = Buffer.from(JSON.stringify({
    service: {metadata: {name: 'loki', uid: 'loki-service'}},
    pod: {metadata: {name: 'loki-0', uid: 'loki-pod'}},
  }) + '\n');
  const teardown = {
    qualifiedTree,
    manifest: {
      schemaVersion: 'stacks-attacknet-teardown-evidence/v1', network: 'attacknet', run: 'baseline',
      networkUID: 'network-uid', inventoryDigest: immutable('3'),
      namespace: 'hacknet-system', start: observedAt, end: '2026-08-26T00:01:00.000Z',
      artifacts: {}, deletionComplete: true,
      completedAt: '2026-08-26T00:02:00.000Z',
    },
  };
  const loki = {
    schemaVersion: 'stacks-attacknet-loki-export/v1', complete: true,
    selector: '{attacknet_network="attacknet"}', startNs: '1', endNs: '2', direction: 'forward',
    pageLimit: 5000, pageCount: 1, entryCount: 1,
    pages: [{page: 1, startNs: '1', rawEntries: 1, newEntries: 1, maximumTimestampNs: '1'}],
    buildInfo: {version: '3.0'}, logArtifact: 'logs.jsonl.gz', compression: 'gzip',
    uncompressedBytes: lokiRaw.length, compressedBytes: lokiLogs.length,
    exportedAt: observedAt,
  };
  const teardownFailure = {
    schemaVersion: 'stacks-attacknet-a8-teardown-failure/v1', qualifiedTree,
    commandFailed: true, networkPreserved: true,
    before: {uid: 'network-uid', inventoryDigest: immutable('3')},
    after: {uid: 'network-uid', inventoryDigest: immutable('3')},
    partialExport: {complete: false, failure: 'pagination stalled'},
  };
  const cleanTeardown = {
    schemaVersion: 'stacks-attacknet-a8-clean-teardown/v1', qualifiedTree,
    completed: true, remainingCounts: {networks: 0, runs: 0, campaigns: 0, chaos: 0, pods: 0, pvcs: 0},
  };
  const incidentArtifact = Buffer.from('{"kind":"StacksNetwork"}\n');
  const incident = {
    schemaVersion: 'stacks-attacknet-incident-evidence/v1', capturedAt: observedAt,
    network: {namespace: 'hacknet-system', name: 'attacknet', uid: 'network-uid'},
    bounds: {}, artifacts: [{
      path: 'resources/network.json', mediaType: 'application/json',
      sha256: `sha256:${bytesDigest(incidentArtifact)}`, bytes: incidentArtifact.length, source: 'kubernetes-api',
    }], omissions: [], errors: [],
  };
  const attacknetRun = {apiVersion: 'testing.stacks.org/v1beta1', kind: 'AttacknetRun', metadata: {name: 'baseline'}};
  return {
    baseline, violation, sourceLoss, stacksTrigger, teardown, loki, lokiLogs, lokiSource,
    incident, incidentArtifact, attacknetRun, teardownFailure, cleanTeardown, root,
  };
}

// Keep the fixture digest synchronous and explicit so corruption controls are
// not coupled to the product digest implementation.
function bytesDigest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value)}\n`);
}

function git(root, ...arguments_) {
  // Qualification runs this suite with Git plumbing bound to the immutable
  // candidate tree. Fixture repositories must not inherit that binding.
  const environment = {...process.env};
  for (const name of ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE', 'GIT_WORK_TREE']) {
    delete environment[name];
  }
  return execFileSync('git', arguments_, {cwd: root, env: environment, encoding: 'utf8'}).trim();
}

/** Commit in a disposable repository without writing fixture identity to Git config. */
function fixtureCommit(root, message) {
  return git(
    root,
    '-c', 'user.name=Attacknet Test',
    '-c', 'user.email=attacknet@example.invalid',
    '-c', 'commit.gpgsign=false',
    'commit', '--quiet', '-m', message,
  );
}

function writeTeardownFixture(input, value) {
  const root = join(input, 'teardown-success');
  writeJSON(join(root, 'attacknet-run.json'), value.attacknetRun);
  mkdirSync(join(root, 'incident', 'resources'), {recursive: true});
  writeFileSync(join(root, 'incident', 'resources', 'network.json'), value.incidentArtifact);
  writeJSON(join(root, 'incident', 'manifest.json'), value.incident);
  writeJSON(join(root, 'loki', 'export.json'), value.loki);
  writeFileSync(join(root, 'loki', 'logs.jsonl.gz'), value.lokiLogs);
  writeFileSync(join(root, 'loki', 'kubernetes-source.json'), value.lokiSource);
  const paths = {
    incident: 'incident/manifest.json', attacknetRun: 'attacknet-run.json',
    lokiMetadata: 'loki/export.json', lokiLogs: 'loki/logs.jsonl.gz',
    lokiSource: 'loki/kubernetes-source.json',
  };
  value.teardown.manifest.artifacts = Object.fromEntries(Object.entries(paths).map(([key, path]) => [
    key, `sha256:${bytesDigest(readFileSync(join(root, path)))}`,
  ]));
  writeJSON(join(root, 'teardown.json'), value.teardown);
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})) {
      const path = join(directory, entry.name);
      const name = relative(root, path);
      if (name === 'inventory.json') continue;
      if (entry.isDirectory()) visit(path);
      else entries.push({path: name, digest: `sha256:${bytesDigest(readFileSync(path))}`, size: statSync(path).size});
    }
  };
  visit(root);
  entries.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  writeJSON(join(root, 'inventory.json'), {
    schemaVersion: 'stacks-attacknet-a8-teardown-inventory/v1', entries,
  });
}

function candidateBuildReceipt() {
  const id = purpose => purpose === 'run-operator' ? immutable('8')
    : `sha256:${bytesDigest(Buffer.from(purpose))}`;
  const runtimeID = purpose => `sha256:${bytesDigest(Buffer.from(`runtime:${purpose}`))}`;
  const installed = A8_INSTALLED_PURPOSES;
  const nodes = ['kind-control-plane', 'kind-worker', 'kind-worker2'].map(name => ({
    name, providerID: `kind://${name}`, operatingSystem: 'linux', architecture: 'arm64',
  }));
  return {
    schemaVersion: 'stacks-attacknet-a8-candidate-build/v1', qualifiedTree, capturedAt: observedAt,
    runOperatorImageID: id('run-operator'),
    actorImage: {purpose: 'stacks-core', ref: 'stacks-core:dev', immutableID: id('stacks-core')},
    build: {
      schemaVersion: 'stacks-attacknet-local-build/v1',
      images: A8_BUILD_PURPOSES.map(purpose => ({purpose, ref: `${purpose}:dev`, id: id(purpose)})),
    },
    install: {
      schemaVersion: 'stacks-attacknet-local-install/v1', namespace: 'hacknet-system', release: 'hacknet',
      images: installed.map(purpose => ({
        purpose, requestedRef: `${purpose}:dev`, immutableID: id(purpose), deploymentRef: `${purpose}:local`,
      })),
      kindImageLoad: {
        schemaVersion: 'stacks-attacknet-kind-image-load/v1', outcome: 'Loaded', nodes,
      images: nodes.flatMap(node => installed.map(purpose => ({
        node: node.name, requestedRef: `${purpose}:local`, importedRef: `${purpose}:local`,
        runtimeImageID: runtimeID(purpose), verified: true,
      }))),
      },
    },
    actorImageLoad: {
      schemaVersion: 'stacks-attacknet-kind-image-load/v1', outcome: 'Loaded', nodes,
      images: nodes.map(node => ({
        node: node.name, requestedRef: 'stacks-core:dev', importedRef: 'stacks-core:dev',
        runtimeImageID: runtimeID('stacks-core'), verified: true,
      })),
    },
  };
}

function candidateRuntime() {
  const receipt = candidateBuildReceipt();
  const builds = new Map(receipt.build.images.map(image => [image.purpose, image.id]));
  const runtime = candidateRuntimeImageIDs(receipt, qualifiedTree);
  const container = (purpose, pod, name, indexed = false) => ({
    purpose, pod, podUID: `${pod}-uid`, container: name, requestedImage: `${purpose}:dev`,
    runtimeImageID: runtime.get(purpose), expectedRuntimeImageID: runtime.get(purpose),
    ...(indexed ? {buildIndex: builds.get(purpose)} : {}),
  });
  return {
    schemaVersion: 'stacks-attacknet-a8-candidate-runtime/v1', capturedAt: observedAt,
    containers: [
      container('topology-operator', 'topology-0', 'operator', true),
      container('run-operator', 'run-0', 'run-operator', true),
      container('burnchain-clock', 'clock-0', 'clock'),
      container('probe', 'bitcoin-0', 'attacknet-probe'),
      container('probe', 'follower-1-0', 'attacknet-probe'),
      container('probe', 'follower-2-0', 'attacknet-probe'),
      container('stacks-core', 'follower-1-0', 'actor'),
      container('stacks-core', 'follower-2-0', 'actor'),
    ],
    builtButNotRunning: ['io-pressure'],
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a8-'));
  const input = join(root, 'raw');
  const output = join(root, 'evidence');
  mkdirSync(input, {recursive: true});
  const value = values(root);
  writeFileSync(join(input, A8_ARTIFACTS.candidateDiff), 'A8 candidate patch\n');
  writeJSON(join(input, A8_ARTIFACTS.verification), verification());
  writeJSON(join(input, A8_ARTIFACTS.attacknetCheck), {
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: qualifiedTree,
    status: 'passed', suites: [{name: 'all', tests: 1, passed: 1, failed: 0}],
  });
  writeJSON(join(input, A8_ARTIFACTS.hacknetCheck), {
    schemaVersion: 'stacks-hacknet-offline-check-result/v1', sourceRevision: qualifiedTree,
    status: 'passed', requiredChecks: ['operator'], optionalChecks: [
      {name: 'go', status: 'passed'}, {name: 'envtest', status: 'passed'}, {name: 'helm', status: 'passed'},
    ],
  });
  writeJSON(join(input, A8_ARTIFACTS.candidateBuild), candidateBuildReceipt());
  writeJSON(join(input, A8_ARTIFACTS.baselineRun), value.baseline);
  writeJSON(join(input, A8_ARTIFACTS.violationRun), value.violation);
  writeJSON(join(input, A8_ARTIFACTS.sourceLossRun), value.sourceLoss);
  writeJSON(join(input, A8_ARTIFACTS.stacksTriggerRun), value.stacksTrigger);
  writeTeardownFixture(input, value);
  writeJSON(join(input, A8_ARTIFACTS.teardownFailure), value.teardownFailure);
  writeJSON(join(input, A8_ARTIFACTS.cleanTeardown), value.cleanTeardown);
  const liveArtifacts = {};
  for (const [key, path] of Object.entries(A8_ARTIFACTS)) {
    if (['candidateDiff', 'verification', 'attacknetCheck', 'hacknetCheck', 'liveQualification'].includes(key)) continue;
    liveArtifacts[key] = {path, digest: `sha256:${bytesDigest(readFileSync(join(input, path)))}`};
  }
  writeJSON(join(input, A8_ARTIFACTS.liveQualification), {
    schemaVersion: 'stacks-attacknet-a8-live-qualification/v1', qualifiedTree,
    outcome: 'Passed', cluster: {provider: 'kind', architecture: 'arm64', nodes: 3},
    candidateRuntime: candidateRuntime(),
    sourceLossControl: sourceLossControl(),
    lokiIngressControl: lokiIngressControl(),
    artifacts: liveArtifacts,
  });
  const summary = assembleA8Evidence({
    qualifiedTree, inputDirectory: input, outputDirectory: output,
    archiveLocation: 'file:///review/release-1-a8-evidence.tar.gz', root,
  });
  const contractDirectory = join(root, 'contrib/attacknet/release/amendments/a8');
  mkdirSync(contractDirectory, {recursive: true});
  cpSync(new URL('./contract.json', import.meta.url), join(contractDirectory, 'contract.json'));
  return {root, input, output, summary, patch: readFileSync(join(input, A8_ARTIFACTS.candidateDiff)), value};
}

function packetInventory() {
  return contract.requiredInventory.map((id, index) => ({
    id,
    kind: id.startsWith('test:') ? 'test'
      : id.startsWith('evidence:') ? 'evidence'
        : id.startsWith('diff:') ? 'diff'
          : id.includes('.md') ? 'document' : 'source',
    path: `review/item-${index}`,
    digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
}

test('A8 verification requires every complete named check', () => {
  const value = verification();
  assert.equal(validateA8Verification(value, qualifiedTree), value);
  value.checks.pop();
  assert.throws(() => validateA8Verification(value, qualifiedTree), /missing/);
});

test('A8 post-sign attestation cannot substitute a different tree, diff, or evidence packet', () => {
  const qualification = verification();
  const summaryDigest = immutable('d');
  const value = {
    schema: A8_CANDIDATE_ATTESTATION_SCHEMA, candidateRevision,
    candidateTree: qualification.qualifiedTree, parentRevision,
    patchDigest: qualification.patchDigest, evidenceSummaryDigest: summaryDigest,
    signatureVerified: true, recordedAt: observedAt,
  };
  assert.equal(validateA8CandidateAttestation(value, qualification, summaryDigest), value);
  for (const [field, replacement] of [
    ['candidateTree', 'f'.repeat(40)], ['patchDigest', immutable('e')],
    ['evidenceSummaryDigest', immutable('e')], ['signatureVerified', false],
  ]) {
    assert.throws(
      () => validateA8CandidateAttestation({...value, [field]: replacement}, qualification, summaryDigest),
      /does not bind/,
    );
  }
});

test('A8 live qualification preserves offline verification and refuses stale live evidence', () => {
  const output = join(mkdtempSync(join(tmpdir(), 'release-one-a8-output-')), 'raw');
  mkdirSync(output, {recursive: true});
  writeJSON(join(output, A8_ARTIFACTS.verification), verification());
  assert.doesNotThrow(() => prepareQualificationOutput(output));
  writeJSON(join(output, A8_ARTIFACTS.baselineRun), {stale: true});
  assert.throws(() => prepareQualificationOutput(output), /refusing to overwrite existing A8 live evidence/);
});

test('A8 live qualification consumes the supported installer build annotation', () => {
  const runtimeImageID = immutable('8');
  const buildIndex = immutable('9');
  const pod = {
    metadata: {name: 'run-operator-1', uid: 'run-uid', annotations: {'attacknet-build': buildIndex}},
    spec: {containers: [{name: 'run-operator', image: 'run-operator:candidate'}]},
    status: {containerStatuses: [{name: 'run-operator', ready: true, imageID: runtimeImageID}]},
  };
  assert.equal(candidateContainerIdentity(
    pod, 'run-operator', 'run-operator', runtimeImageID, buildIndex,
  ).buildIndex, buildIndex);
  pod.metadata.annotations = {'testing.stacks.org/build-index': runtimeImageID};
  assert.throws(
    () => candidateContainerIdentity(pod, 'run-operator', 'run-operator', runtimeImageID, buildIndex),
    /does not match the expected candidate image/,
  );
});

test('A8 candidate build receipt binds every installed image to all kind nodes', () => {
  const value = candidateBuildReceipt();
  assert.equal(validateCandidateBuildReceipt(value, qualifiedTree), value);
  assert.notEqual(
    candidateRuntimeImageIDs(value, qualifiedTree).get('run-operator'),
    value.runOperatorImageID,
  );
  value.install.images[0].immutableID = immutable('f');
  assert.throws(() => validateCandidateBuildReceipt(value, qualifiedTree), /did not use the built/);
  const stale = candidateBuildReceipt();
  stale.install.kindImageLoad.images[0].runtimeImageID = immutable('f');
  assert.throws(() => validateCandidateBuildReceipt(stale, qualifiedTree), /inconsistent runtime image/);
  const unknownNode = candidateBuildReceipt();
  unknownNode.install.kindImageLoad.images[0].node = 'kind-unknown';
  assert.throws(() => validateCandidateBuildReceipt(unknownNode, qualifiedTree), /kind image admission/);
});

test('A8 source-loss intervention refuses a campaign whose active window was missed', () => {
  assert.equal(observesActiveFaultCampaign({status: {phase: 'Pending'}}), false);
  assert.equal(observesActiveFaultCampaign({status: {phase: 'Running'}}), true);
  for (const phase of ['Passed', 'Failed', 'Inconclusive']) {
    assert.throws(
      () => observesActiveFaultCampaign({status: {phase}}),
      new RegExp(`became ${phase} before Service withdrawal`),
    );
  }
});

test('A8 run validators distinguish baseline, violation, and source loss', () => {
  const value = values('unused');
  assert.equal(validateA8BaselineRun(value.baseline, qualifiedTree), value.baseline);
  assert.equal(validateA8ViolationRun(value.violation, qualifiedTree), value.violation);
  assert.equal(validateA8SourceLossRun(value.sourceLoss, qualifiedTree), value.sourceLoss);
  assert.equal(validateA8StacksTriggerRun(value.stacksTrigger, qualifiedTree), value.stacksTrigger);
  value.sourceLoss.resource.status.phase = 'Passed';
  assert.throws(() => validateA8SourceLossRun(value.sourceLoss, qualifiedTree), /Inconclusive/);
});

test('A8 source-loss control binds Service withdrawal and exact restoration', () => {
  const value = sourceLossControl();
  const run = values('unused').sourceLoss.resource;
  assert.equal(validateA8SourceLossControl(value, run), value);
  value.service.restoredUID = value.service.beforeUID;
  assert.throws(() => validateA8SourceLossControl(value, run), /Service withdrawal/);
  const wrongRun = sourceLossControl();
  wrongRun.run.uid = 'replacement-run';
  assert.throws(() => validateA8SourceLossControl(wrongRun, run), /Service withdrawal/);
});

test('A8 Loki ingress control requires both allowed and denied network paths', () => {
  const value = lokiIngressControl();
  assert.equal(validateA8LokiIngressControl(value), value);
  value.outcomes[1].expectedReachable = true;
  assert.throws(() => validateA8LokiIngressControl(value), /did not prove/);
  const duplicated = lokiIngressControl();
  duplicated.outcomes.push(structuredClone(duplicated.outcomes[0]));
  assert.throws(() => validateA8LokiIngressControl(duplicated), /incomplete/);
});

test('A8 failed export must preserve the exact network identity', () => {
  const value = values('unused').teardownFailure;
  assert.equal(validateA8TeardownFailure(value, qualifiedTree), value);
  value.after.uid = 'replacement';
  assert.throws(() => validateA8TeardownFailure(value, qualifiedTree), /exact network identity/);
});

test('A8 teardown binds the complete log corpus and exact Loki source', () => {
  const value = fixture();
  assert.match(value.value.incident.artifacts[0].sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateA8Teardown(
    value.value.teardown, value.value.loki, join(value.input, 'teardown-success'), qualifiedTree,
  ), value.value.teardown);
  value.value.teardown.manifest.artifacts.lokiSource = immutable('f');
  assert.throws(() => validateA8Teardown(
    value.value.teardown, value.value.loki, join(value.input, 'teardown-success'), qualifiedTree,
  ), /does not bind lokiSource/);
  const wrongRange = fixture();
  wrongRange.value.loki.pages[0].maximumTimestampNs = '3';
  assert.throws(() => validateA8Teardown(
    wrongRange.value.teardown, wrongRange.value.loki,
    join(wrongRange.input, 'teardown-success'), qualifiedTree,
  ), /outside the export range/);
});

test('A8 assembler produces a portable complete evidence archive', () => {
  const value = fixture();
  assert.deepEqual(Object.keys(value.summary.artifacts).sort(), Object.keys(A8_ARTIFACTS).sort());
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
  assert.ok(!JSON.stringify(value.summary).includes(value.root));
});

function validatePortableFixture(value, summary = value.summary) {
  return validatePortableLiveSummary(summary, {sourceRevision: candidateRevision, commitPending: false}, {
    root: value.root, schema: A8_SUMMARY_SCHEMA, checkpoint: 'A8',
    requiredArtifacts: Object.keys(A8_ARTIFACTS), requiredAssertions: A8_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: qualifiedTree, description: 'qualified tree'},
  });
}

test('portable evidence rejects corrupt, extra, duplicate, and trailing archive data', async t => {
  const original = fixture();
  assert.equal(validatePortableFixture(original), original.summary);
  for (const mode of ['corrupt', 'extra', 'duplicate', 'trailing']) {
    await t.test(mode, () => {
      const extracted = join(original.root, `archive-${mode}`);
      mkdirSync(extracted);
      execFileSync('tar', ['-xzf', join(original.root, original.summary.archive.path), '-C', extracted]);
      if (mode === 'corrupt') {
        writeFileSync(join(extracted, 'artifacts', A8_ARTIFACTS.baselineRun), 'corrupt\n');
      }
      if (mode === 'extra') writeFileSync(join(extracted, 'unindexed.txt'), 'extra\n');
      const tarPath = join(original.root, `${mode}.tar`);
      execFileSync('tar', ['-cf', tarPath, '-C', extracted, 'archive-index.json', 'artifacts',
        ...(mode === 'extra' ? ['unindexed.txt'] : [])], {env: {...process.env, COPYFILE_DISABLE: '1'}});
      if (mode === 'duplicate') {
        execFileSync('tar', ['-rf', tarPath, '-C', extracted, `artifacts/${A8_ARTIFACTS.baselineRun}`], {
          env: {...process.env, COPYFILE_DISABLE: '1'},
        });
      }
      if (mode === 'trailing') appendFileSync(tarPath, 'not-tar-padding');
      const archivePath = `${tarPath}.gz`;
      writeFileSync(archivePath, gzipSync(readFileSync(tarPath)));
      const summary = structuredClone(original.summary);
      summary.archive.path = archivePath;
      summary.archive.digest = `sha256:${bytesDigest(readFileSync(archivePath))}`;
      assert.throws(
        () => validatePortableFixture(original, summary),
        /unindexed|duplicates|does not match|trailing data/,
      );
    });
  }
});

test('A8 packet is Full and binds the exact candidate diff', () => {
  const value = fixture();
  const candidate = {sourceRevision: candidateRevision, commitPending: false, dirtyPatchDigest: immutable('0')};
  const options = {
    root: value.root, candidate, summaryPath: join(value.output, 'summary.json'),
    inventory: packetInventory(), candidateScope: {parent: 'f'.repeat(40), paths: []},
    candidateDiff: value.patch,
    signedCandidateBinding: {
      schema: 'stacks-attacknet-release-1-a8-candidate-attestation/v1',
      candidateRevision, candidateTree: qualifiedTree, parentRevision,
      patchDigest: verification().patchDigest,
      evidenceSummaryDigest: `sha256:${bytesDigest(readFileSync(join(value.output, 'summary.json')))}`,
      signatureVerified: true, recordedAt: observedAt,
    },
    qualifiedCandidateTree: qualifiedTree,
  };
  const packet = buildA8Packet(options);
  assert.equal(packet.reviewId, 'release-1-amendment-a8-trusted-observations');
  assert.equal(packet.tier, 'Full');
  assert.equal(packet.compatibility.evidenceInterpretationChanged, true);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(() => buildA8Packet({...options, candidateDiff: Buffer.from('wrong')}), /candidate diff artifact/);
  assert.throws(() => buildA8Packet({
    ...options, signedCandidateBinding: {...options.signedCandidateBinding, candidateTree: 'c'.repeat(40)},
  }), /does not bind/);
});

test('A8 contract makes trusted observations, teardown, and live proof load-bearing', () => {
  for (const id of [
    'candidate:contrib/helm/hacknet/operator/internal/protocolobservation/reader.go',
    'candidate:contrib/helm/hacknet/operator/internal/protocolassertion/evaluator.go',
    'candidate:contrib/helm/hacknet/operator/internal/attacknetcli/teardown.go',
    'candidate:contrib/attacknet/observability/dashboards/attacknet-overview.json',
    'candidate:contrib/attacknet/release/amendments/a8/qualification/live.mjs',
    'evidence:live-qualification', 'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});

test('A8 whole-product results bind the qualified tree before signing', () => {
  for (const path of ['contrib/attacknet/test/check.sh', 'contrib/helm/hacknet/scripts/check.sh']) {
    const source = readFileSync(join(repositoryRoot, path), 'utf8');
    assert.match(source, /ATTACKNET_QUALIFIED_TREE/);
  }
  assert.match(
    readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8'),
    /const qualification = requireA8QualifiedTree\(qualifiedTree\);/,
  );
});

test('A8 qualification materializes only the exact staged Git tree', t => {
  const repository = mkdtempSync(join(tmpdir(), 'attacknet-a8-git-'));
  t.after(() => rmSync(repository, {recursive: true, force: true}));
  git(repository, 'init', '--quiet');
  writeFileSync(join(repository, '.gitignore'), 'ignored.txt\n');
  writeFileSync(join(repository, 'tracked.txt'), 'committed\n');
  git(repository, 'add', '.gitignore', 'tracked.txt');
  fixtureCommit(repository, 'fixture');
  writeFileSync(join(repository, 'tracked.txt'), 'qualified staged bytes\n');
  writeFileSync(join(repository, 'ignored.txt'), 'must not enter qualification\n');
  git(repository, 'add', 'tracked.txt');
  const tree = git(repository, 'write-tree');
  const materialized = materializeQualifiedTree(repository, tree);
  t.after(materialized.cleanup);
  assert.equal(readFileSync(join(materialized.sourceRoot, 'tracked.txt'), 'utf8'), 'qualified staged bytes\n');
  assert.throws(() => readFileSync(join(materialized.sourceRoot, 'ignored.txt')), /ENOENT/);
});

test('A8 materialization preserves linked-worktree HEAD identity', t => {
  const repository = mkdtempSync(join(tmpdir(), 'attacknet-a8-worktree-'));
  t.after(() => rmSync(repository, {recursive: true, force: true}));
  git(repository, 'init', '--quiet');
  writeFileSync(join(repository, 'tracked.txt'), 'first\n');
  git(repository, 'add', 'tracked.txt');
  fixtureCommit(repository, 'first');
  const worktreeHead = git(repository, 'rev-parse', 'HEAD');
  writeFileSync(join(repository, 'tracked.txt'), 'primary\n');
  git(repository, 'add', 'tracked.txt');
  fixtureCommit(repository, 'primary');
  const linked = join(repository, 'linked');
  git(repository, 'worktree', 'add', '--quiet', '--detach', linked, worktreeHead);
  writeFileSync(join(linked, 'tracked.txt'), 'qualified\n');
  git(linked, 'add', 'tracked.txt');
  const tree = git(linked, 'write-tree');
  const repositoryConfigBefore = git(repository, 'config', '--local', '--list');
  const materialized = materializeQualifiedTree(linked, tree);
  t.after(materialized.cleanup);
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: materialized.sourceRoot, env: materialized.environment, encoding: 'utf8',
  }).trim(), worktreeHead);
  assert.equal(readFileSync(join(materialized.sourceRoot, 'tracked.txt'), 'utf8'), 'qualified\n');
  git(materialized.sourceRoot, 'config', 'attacknet.fixture', 'isolated');
  assert.equal(git(repository, 'config', '--local', '--list'), repositoryConfigBefore);
});

test('A8 materialized entrypoints compare canonical filesystem identity', t => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a8-entrypoint-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const target = join(directory, 'entry.mjs');
  const alias = join(directory, 'entry-alias.mjs');
  writeFileSync(target, 'export {};\n');
  symlinkSync(target, alias);
  assert.equal(isMainModule(pathToFileURL(target), alias), true);
  const previous = process.env.ATTACKNET_A8_MATERIALIZED_SOURCE;
  process.env.ATTACKNET_A8_MATERIALIZED_SOURCE = alias;
  try {
    assert.equal(isMaterializedSource(target), true);
  } finally {
    if (previous === undefined) delete process.env.ATTACKNET_A8_MATERIALIZED_SOURCE;
    else process.env.ATTACKNET_A8_MATERIALIZED_SOURCE = previous;
  }
});

test('A8 qualification resources pass the production typed CLI decoder', () => {
  const qualification = new URL('./qualification/', import.meta.url);
  const files = readdirSync(qualification).filter(name => name.endsWith('.yaml')).sort();
  assert.equal(files.length, 8);
  for (const file of files) {
    execFileSync('go', [
      'run', './cmd/attacknet', 'validate', '--file', new URL(file, qualification).pathname,
      '--namespace', 'hacknet-system', '--output', 'json',
    ], {cwd: join(repositoryRoot, 'contrib/helm/hacknet/operator'), stdio: 'pipe'});
  }
});
