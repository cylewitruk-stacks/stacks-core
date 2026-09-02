import assert from 'node:assert/strict';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import test from 'node:test';

import {
  validateA13Advisory, validateA13AttacknetCheck, validateA13Capacity,
  validateA13Corpus, validateA13EvidenceOutput, validateA13FiniteSession, validateA13LiveResult,
  validateA13NonReproduction, validateA13Planning, validateA13Reduction, validateA13Resume, validateA13Teardown,
  burnchainCrossings, isImmutableRuntimeImageID, validateRemovalOnlyRelation,
} from './evidence.mjs';
import {isA13PathPermitted} from './packet.mjs';
import {
  canonicalDigest, fuzzSessionReservation, listItems, scopedCountsFromLists,
} from './qualification/support.mjs';
import {
  a13BehaviorPolicyDigest, admittedVersionCohortAssignments, advisoryPlanReference,
  bindMinimalReductionTarget, reductionTemplatePlans,
  bindExternalConfigDigest, lastHarnessFailure, liveIdentityMatchesJournal,
  nonReproductionAssertions, nonReproductionControlReady, nonReproductionTemplatePlan,
  observedAttemptResources, preservesExecutionOrder, resumeResourceAnomalyCount, sealAdvisory,
} from './qualification/live.mjs';

const tree = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const pass = (schemaVersion, rest = {}) => ({qualifiedTree: tree, schemaVersion, outcome: 'Passed', ...rest});

test('A13 clean-scope lists preserve an empty Kubernetes List document', () => {
  let arguments_;
  const items = listItems('attacknetruns.testing.stacks.org', value => {
    arguments_ = value;
    return {apiVersion: 'v1', kind: 'List', items: []};
  });
  assert.deepEqual(items, []);
  assert.deepEqual(arguments_, [
    '-n', 'hacknet-system', 'get', 'attacknetruns.testing.stacks.org',
  ]);
});

test('A13 evidence-loss control recognizes specific fail-closed journal kinds', () => {
  const records = [
    {kind: 'NetworkObserved', phase: 'TrialPreparing'},
    {kind: 'EvidenceCaptureFailed', phase: 'HarnessFailed', digest: digest('e')},
  ];
  assert.equal(lastHarnessFailure(records)?.kind, 'EvidenceCaptureFailed');
  assert.equal(lastHarnessFailure([{kind: 'TrialComplete', phase: 'Complete'}]), undefined);
});

test('A13 planning and capacity controls are load-bearing', () => {
  const planning = pass('stacks-attacknet-a13-planning-controls/v1', {
    sameSeedByteIdentical: true, templateDriftRejected: true,
    mutationsBefore: 7, mutationsAfter: 7, descriptorDigest: digest('b'),
    materializationAlgorithm: 'attacknet-resource-materializer/v1',
  });
  assert.equal(validateA13Planning(planning, tree), planning);
  assert.throws(() => validateA13Planning({...planning, mutationsAfter: 8}, tree), /planning controls/);
  const capacity = pass('stacks-attacknet-a13-capacity-control/v1', {
    insufficientCapacityRejected: true, networksCreated: 0,
    physicalEscrowVerified: true, nodeCount: 3, receiptDigest: digest('c'),
  });
  assert.equal(validateA13Capacity(capacity, tree), capacity);
  assert.throws(() => validateA13Capacity({...capacity, networksCreated: 1}, tree), /capacity control/);
});

test('A13 reduction controls target an enrolled peer in the minimal topology', () => {
  const campaign = {spec: {stages: [{faults: [{fault: {parameters: {
    direction: 'both', harnessTarget: 'prometheus', delay: {latency: '150ms'},
  }}}]}]}};
  assert.equal(bindMinimalReductionTarget(campaign), campaign);
  assert.equal(campaign.spec.stages[0].faults[0].fault.parameters.harnessTarget, undefined);
  assert.deepEqual(campaign.spec.stages[0].faults[0].fault.parameters.peerTarget,
    {actors: ['bitcoin'], mode: 'all'});
  assert.throws(() => bindMinimalReductionTarget(structuredClone(campaign)), /expected Prometheus target/);
});

test('A13 same-probe reduction controls execute sequentially', () => {
  const templates = reductionTemplatePlans();
  assert.deepEqual(templates.map(template => ({id: template.id, requires: template.requires ?? []})), [
    {id: 'reduce-a', requires: []},
    {id: 'reduce-b', requires: ['reduce-a']},
    {id: 'reduce-c', requires: ['reduce-b']},
  ]);
  assert.equal(new Set(templates.map(template => template.name)).size, 3);
  assert.ok(templates.every(template => template.maxUses === 1));
});

test('A13 non-reproduction control uses the minimal topology enrolled-peer probe', () => {
  assert.deepEqual(nonReproductionTemplatePlan(), {
    id: 'delay', kind: 'FaultCampaign', name: 'a13-reduce-a', weight: 1, maxUses: 1,
  });
});

test('A13 advisory and resume validators reject incomplete proof', () => {
  const advisory = pass('stacks-attacknet-a13-advisory-controls/v1', {
    outOfUniverseRejected: true, mutationsBefore: 2, mutationsAfter: 2,
    acceptedRetained: true, corpusOnlyReplay: true,
    missingObjectRejected: true, substitutedObjectRejected: true,
    advisoryObjectDigest: digest('d'),
  });
  assert.equal(validateA13Advisory(advisory, tree), advisory);
  assert.throws(() => validateA13Advisory({...advisory, corpusOnlyReplay: false}, tree), /advisory controls/);
  const resume = pass('stacks-attacknet-a13-resume-controls/v1', {
    finalPhase: 'Complete', duplicateResources: 0,
    interruptions: ['network-creation', 'active-execution', 'evidence-capture', 'teardown']
      .map(stage => ({stage, resumed: true, identityPreserved: true,
        expectedIdentityDigest: digest('f'), resumedIdentityDigest: digest('f'),
        ...(stage === 'evidence-capture' ? {plannedGenerationTransition: {
          fromGeneration: 1, toGeneration: 2, observedGeneration: 2, phase: 'Suspended',
        }} : {})})),
  });
  assert.equal(validateA13Resume(resume, tree), resume);
  assert.throws(() => validateA13Resume({...resume, duplicateResources: 1}, tree), /resume controls/);
  const mismatched = structuredClone(resume);
  mismatched.interruptions[0].resumedIdentityDigest = digest('e');
  assert.throws(() => validateA13Resume(mismatched, tree), /resume controls/);
});

test('A13 resume identity permits only the exact planned suspension transition', () => {
  const journaled = {kind: 'StacksNetwork', uid: 'network-uid', generation: 1};
  const suspended = {uid: 'network-uid', generation: 2, observedGeneration: 2, phase: 'Suspended'};
  assert.equal(liveIdentityMatchesJournal(journaled, suspended), false);
  assert.equal(liveIdentityMatchesJournal(journaled, suspended, {plannedNetworkSuspension: true}), true);
  assert.equal(liveIdentityMatchesJournal(journaled,
    {...suspended, generation: 3, observedGeneration: 3}, {plannedNetworkSuspension: true}), false);
  assert.equal(liveIdentityMatchesJournal(journaled,
    {...suspended, uid: 'replacement-uid'}, {plannedNetworkSuspension: true}), false);
});

test('A13 non-reproduction control waits for the sealed recovery baseline', () => {
  const run = {status: {phase: 'Running', reason: 'ProtocolRecoveryPending',
    protocolAssertions: {recovery: {startedAt: '2026-01-01T00:00:00Z'}}}};
  assert.equal(nonReproductionControlReady(run), true);
  assert.equal(nonReproductionControlReady({...run,
    status: {...run.status, reason: 'CampaignsActive'}}), false);
  assert.equal(nonReproductionControlReady({...run,
    status: {...run.status, protocolAssertions: {recovery: {}}}}), false);
  assert.deepEqual(nonReproductionAssertions(), {
    timeout: '70s', assertions: [{id: 'bounded-progress', chainProgress: {
      chain: 'burnchain', actors: ['follower-1'], window: '60s', minimumDelta: 15,
    }}],
  });
});

test('A13 non-reproduction evidence binds the source-only cadence-policy control', () => {
  const value = pass('stacks-attacknet-a13-non-reproduction/v1', {
    classification: 'NotReproduced', retained: true, reductionAttempted: false,
    sourceNetworkUID: 'source-uid', replayNetworkUID: 'replay-uid',
    qualificationControl: 'bounded-recovery-window-burnchain-policy-pause',
    pauseProof: {policyUID: 'policy-uid', policyGeneration: 2, observedHeight: 123,
      stableForSeconds: 5, recoveryStartedAt: '2026-01-01T00:00:00Z'},
  });
  assert.equal(validateA13NonReproduction(value, tree), value);
  assert.throws(() => validateA13NonReproduction({...value,
    qualificationControl: 'unbound-control'}, tree), /non-reproduction/);
});

test('A13 advisory plan references retain their bounded trial ordinal', () => {
  assert.deepEqual(advisoryPlanReference({
    path: '/tmp/advisory.json', value: {trialOrdinal: 3},
  }), {trialOrdinal: 3, file: 'advisory.json'});
  assert.throws(() => advisoryPlanReference({path: '/tmp/advisory.json', value: {}}), /trial ordinal/);
});

test('A13 mixed-version proof reads typed actor status images and Kubernetes image IDs', () => {
  const candidate = digest('a');
  const stable = digest('b');
  const source = {spec: {
    defaults: {nodeImage: 'node:candidate'},
    nodes: [{name: 'miner-1'}, {name: 'follower-1', image: 'node:stable'}],
  }};
  const actors = [
    {name: 'bitcoin', role: 'burnchain', image: 'bitcoin:regtest',
      runtimeImageID: `containerd://${digest('c')}`},
    {name: 'follower-1', role: 'follower', image: 'node:stable', runtimeImageID: stable},
    {name: 'miner-1', role: 'miner', image: 'node:candidate', runtimeImageID: candidate},
  ];
  const result = admittedVersionCohortAssignments(actors, source);
  assert.deepEqual(result.assignments.map(item => [item.actor, item.requestedImage]), [
    ['follower-1', 'node:stable'], ['miner-1', 'node:candidate'],
  ]);
  assert.throws(() => admittedVersionCohortAssignments(
    actors.map(actor => actor.name === 'follower-1' ? {...actor, runtimeImageID: candidate} : actor), source,
  ), /two distinct admitted immutable node-version cohorts/);
});

test('A13 runtime image evidence accepts one unambiguous Kubernetes digest', () => {
  const immutable = digest('d');
  assert.equal(isImmutableRuntimeImageID(immutable), true);
  assert.equal(isImmutableRuntimeImageID(`containerd://${immutable}`), true);
  assert.equal(isImmutableRuntimeImageID(`registry.example/stacks@${immutable}`), true);
  assert.equal(isImmutableRuntimeImageID('registry.example/stacks:latest'), false);
  assert.equal(isImmutableRuntimeImageID(`${immutable}-${digest('e')}`), false);
});

test('A13 behavior template binds the production signer-policy digest vector', () => {
  assert.equal(a13BehaviorPolicyDigest,
    'sha256:001f1de4c48eba8a2023070deb668b4ef8a1ead728d00886d8898621e1f76c1b');
});

test('A13 external configuration digest binds the ConfigSource, not its Secret reference', () => {
  const source = {secretRef: {name: 'actor-config', key: 'config.toml'}};
  const digest_ = bindExternalConfigDigest(source, new Map([['actor-config', {
    stringData: {'config.toml': 'working_configuration = true\n'},
  }]]));
  assert.match(digest_, /^sha256:[0-9a-f]{64}$/);
  assert.equal(source.expectedDigest, digest_);
  assert.equal(source.secretRef.expectedDigest, undefined);
});

test('A13 advisory sealing retains the production empty-digest field', () => {
  const sealed = sealAdvisory(1, [
    {id: 'beta', score: 1, rationale: 'bounded secondary choice'},
    {id: 'alpha', score: 10, rationale: 'bounded preferred choice'},
  ]);
  assert.deepEqual(sealed.candidates.map(candidate => candidate.id), ['alpha', 'beta']);
  assert.equal(sealed.digest, 'sha256:58f51cec23674efc8accad74a4475d5061fdcc83e2ca54e84b0b806cfde03e4d');
  assert.equal(canonicalDigest({...sealed, digest: ''}), sealed.digest);
});

test('A13 reducer proof binds the exact retained removal instructions', () => {
  const source = [1, 2, 3, 4].map(index => ({id: `execution-${index}`, stages: [{id: 'stage', actions: [{
    id: 'action', actors: ['follower-1'],
  }]}]}));
  const retained = [{executionId: 'execution-1'}];
  const candidate = {algorithm: 'deterministic-hierarchical-ddmin/v1', attempt: 1,
    level: 'execution', retained, digest: ''};
  candidate.digest = canonicalDigest(retained);
  assert.notEqual(canonicalDigest({...candidate, digest: ''}), candidate.digest);
  const reduction = pass('stacks-attacknet-a13-reduction/v1', {
    classification: 'ConfirmedNetworkFailure', sourceExecutionCount: 4,
    reducedExecutionCount: 1, sourceOrderPreserved: true, removalOnly: true,
    causalMinimalityClaimed: false, freshNetworkUIDs: true, graphDigest: digest('e'),
    source, sourceDigest: canonicalDigest(source), retained, retainedDigest: canonicalDigest(retained),
    algorithm: candidate.algorithm, attempts: [{candidate, outcome: 'Reproduced'}],
    sourceBudgets: {maxCampaigns: 4}, reducedBudgets: {maxCampaigns: 4},
  });
  assert.equal(validateA13Reduction(reduction, tree), reduction);
  assert.throws(() => validateA13Reduction({...reduction, causalMinimalityClaimed: true}, tree), /reduction/);
  assert.throws(() => validateA13Reduction({...reduction, reducedExecutionCount: 4}, tree), /reduction/);
  const substituted = structuredClone(reduction);
  substituted.attempts[0].candidate.digest = digest('f');
  assert.throws(() => validateA13Reduction(substituted, tree), /removal-only/);
  const parameterSource = structuredClone(reduction);
  parameterSource.source[0].stages[0].actions[0].monotoneParameters = ['latency'];
  assert.throws(() => validateA13Reduction(parameterSource, tree),
    /automatic parameter reduction is deferred/);
  const parameterCandidate = structuredClone(reduction);
  parameterCandidate.attempts[0].candidate.retained[0].removedParameters = ['stage/action/latency'];
  assert.throws(() => validateA13Reduction(parameterCandidate, tree),
    /automatic parameter reduction is deferred/);
});

test('A13 finite-session proof requires both controller Pod identities to change', () => {
  const assignments = [
    {actor: 'follower-1', role: 'follower', requestedImage: 'stable',
      runtimeImageID: `docker.io/library/stacks-core@${digest('1')}`},
    {actor: 'miner-1', role: 'miner', requestedImage: 'candidate', runtimeImageID: digest('2')},
  ];
  const protocolSchedule = {epochs: [{name: 'epoch-3', startHeight: 121}],
    rewardCycle: {firstHeight: 0, cycleLength: 20, prepareLength: 5}};
  const finite = pass('stacks-attacknet-a13-finite-session/v1', {
    phase: 'Complete', completedTrials: 4,
    faultFamilies: ['fault:network', 'fault:pod', 'fault:clock-skew', 'fault:signer-behavior'],
    a11VersionCohort: true, a12BehaviorTemplate: true,
    crossedBurnchainBoundary: true, evidenceComplete: true,
    controllerRestarts: [
      {deployment: 'hacknet', beforePodUIDs: ['topology-before'], afterPodUIDs: ['topology-after']},
      {deployment: 'hacknet-run', beforePodUIDs: ['run-before'], afterPodUIDs: ['run-after']},
    ],
    sessionDigest: digest('a'), versionCohortDigest: canonicalDigest(assignments),
    versionCohortProof: {networkUID: 'network-uid', inventoryDigest: digest('b'), assignments,
      runStatusAssignments: assignments.map(item => ({name: item.actor,
        requestedImage: item.requestedImage, runtimeImageID: item.runtimeImageID})),
      runStatusCohortDigest: canonicalDigest(assignments.map(item => ({name: item.actor,
        requestedImage: item.requestedImage, runtimeImageID: item.runtimeImageID})))},
    burnchainBoundaryProof: {policyName: 'burn', policyUID: 'burn-uid', startHeight: 118, endHeight: 122,
      protocolSchedule, scheduleDigest: canonicalDigest(protocolSchedule),
      crossings: burnchainCrossings(118, 122, protocolSchedule)},
    advisoryEntryDigest: digest('c'), operatorSurface: {
      statusSchemaVersion: 'stacks-attacknet-fuzz-status/v1', decodedReport: true,
      reportDigest: digest('d'), capacityDigest: digest('e'), corpusValid: true,
      listedEntries: 4, showedEntryDigest: digest('c'), classificationCounts: {Clean: 4,
        NetworkFailureCandidate: 0, ConfirmedNetworkFailure: 0, NotReproduced: 0,
        Inconclusive: 0, HarnessFailed: 0},
      capacityHeadroom: {nodes: ['one', 'two', 'three'].map(name => ({name, rootBytes: 1, imageBytes: 1})),
        corpusBytes: 1},
    },
  });
  assert.equal(validateA13FiniteSession(finite, tree), finite);
  const unchanged = structuredClone(finite);
  unchanged.controllerRestarts[1].afterPodUIDs = ['run-before'];
  assert.throws(() => validateA13FiniteSession(unchanged, tree), /finite session/);
  const sameImage = structuredClone(finite);
  sameImage.versionCohortProof.assignments[1].runtimeImageID = assignments[0].runtimeImageID;
  sameImage.versionCohortDigest = canonicalDigest(sameImage.versionCohortProof.assignments);
  assert.throws(() => validateA13FiniteSession(sameImage, tree), /distinct admitted immutable/);
  const noCrossing = structuredClone(finite);
  noCrossing.burnchainBoundaryProof.startHeight = 122;
  noCrossing.burnchainBoundaryProof.endHeight = 123;
  noCrossing.burnchainBoundaryProof.crossings = [];
  assert.throws(() => validateA13FiniteSession(noCrossing, tree), /actual declared burnchain-boundary/);
});

test('A13 finite proof rejects a threshold without an actual declared boundary crossing', () => {
  const schedule = {epochs: [{name: 'later', startHeight: 203}],
    rewardCycle: {firstHeight: 0, cycleLength: 20, prepareLength: 5}};
  assert.deepEqual(burnchainCrossings(121, 139, schedule), []);
  assert.deepEqual(burnchainCrossings(118, 121, schedule), [
    {kind: 'reward-cycle', name: 'reward-cycle-6', height: 120},
  ]);
});

test('A13 evidence and source paths are constrained', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-a13-paths-'));
  assert.equal(validateA13EvidenceOutput(join(root, 'input'), join(root, 'output')), resolve(root, 'output'));
  assert.throws(() => validateA13EvidenceOutput(join(root, 'input'), join(root, 'input', 'output')), /isolated/);
  assert.throws(() => validateA13EvidenceOutput(join(root, 'input'), join(process.cwd(), 'contrib', 'attacknet', '.a13-output')), /isolated/);
  assert.throws(() => validateA13EvidenceOutput(join(root, 'input'), resolve(process.cwd(), '..')), /isolated/);
  assert.equal(isA13PathPermitted('contrib/attacknet/docs/operations/fuzzing.md'), true);
  assert.equal(isA13PathPermitted('contrib/helm/hacknet/operator/internal/fuzzplan/planner.go'), true);
  assert.equal(isA13PathPermitted('stacks-node/src/main.rs'), false);
});

test('A13 evidence validators reject omitted proof fields', () => {
  assert.throws(() => validateA13AttacknetCheck({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: tree,
    status: 'passed', suites: [{failed: 0}],
  }, tree), /Attacknet check/);
  assert.throws(() => validateA13Planning(pass('stacks-attacknet-a13-planning-controls/v1', {
    sameSeedByteIdentical: true, templateDriftRejected: true,
    descriptorDigest: digest('a'), materializationAlgorithm: 'attacknet-resource-materializer/v1',
  }), tree), /planning controls/);
  assert.throws(() => validateA13Advisory(pass('stacks-attacknet-a13-advisory-controls/v1', {
    outOfUniverseRejected: true, acceptedRetained: true, corpusOnlyReplay: true,
    missingObjectRejected: true, substitutedObjectRejected: true,
    advisoryObjectDigest: digest('a'),
  }), tree), /advisory controls/);
  assert.throws(() => validateA13Reduction(pass('stacks-attacknet-a13-reduction/v1', {
    classification: 'ConfirmedNetworkFailure', sourceOrderPreserved: true,
    removalOnly: true, causalMinimalityClaimed: false, freshNetworkUIDs: true,
    graphDigest: digest('a'),
  }), tree), /reduction/);
  assert.throws(() => validateA13Corpus(pass('stacks-attacknet-a13-corpus-verification/v1', {
    valid: true, cleanCheckoutVerified: true, indexDigest: digest('a'),
    archiveDigest: digest('b'),
  }), tree), /corpus/);
  assert.throws(() => validateA13Teardown(pass('stacks-attacknet-a13-clean-teardown/v1'), tree), /teardown/);
  assert.throws(() => validateA13LiveResult(pass('stacks-attacknet-a13-live-qualification/v1', {
    architecture: 'arm64', kindNodes: ['a', 'b', 'c'],
  }), tree), /live qualification/);
});

test('A13 teardown detects capacity reservations by their production annotation', () => {
  const annotation = {metadata: {annotations: {'testing.stacks.org/fuzz-session': digest('a')}}};
  const legacyLabel = {metadata: {labels: {'testing.stacks.org/fuzz-session': digest('a')}}};
  assert.equal(fuzzSessionReservation(annotation), true);
  assert.equal(fuzzSessionReservation(legacyLabel), true);
  assert.equal(fuzzSessionReservation({metadata: {}}), false);
});

test('A13 teardown counts PVCs through the exact admitted network label and fails on absent lists', () => {
  const empty = {runs: [], faultCampaigns: [], upgradeCampaigns: [], policies: [], leases: [], jobs: []};
  const network = {metadata: {name: 'a13-network'}};
  const pvc = {metadata: {name: 'data-a13-network-follower-1-0', labels: {
    'testing.stacks.org/network': 'a13-network',
  }}};
  const counts = scopedCountsFromLists({...empty, networks: [network], persistentVolumeClaims: [pvc]});
  assert.equal(counts.networks, 1);
  assert.equal(counts.persistentVolumeClaims, 1);
  assert.throws(() => scopedCountsFromLists({...empty, networks: [network]}), /successful complete Kubernetes list/);
});

test('A13 resume proof detects duplicate observations and changed identities', () => {
  const resource = (kind, name, uid) => ({kind, namespace: 'hacknet-system', name, uid, generation: 1});
  const records = [
    {kind: 'PoliciesObserved', trialOrdinal: 1, attemptId: 'source',
      resources: [resource('BurnchainPolicy', 'policy', 'policy-uid')]},
    {kind: 'NetworkObserved', trialOrdinal: 1, attemptId: 'source',
      resources: [resource('StacksNetwork', 'network', 'network-uid')]},
    {kind: 'RunObserved', trialOrdinal: 1, attemptId: 'source',
      resources: [resource('AttacknetRun', 'run', 'run-uid')]},
  ];
  assert.equal(resumeResourceAnomalyCount(records), 0);
  assert.equal(observedAttemptResources(records).length, 3);
  assert.equal(resumeResourceAnomalyCount([...records, structuredClone(records[1])]), 2);
  const replaced = structuredClone(records[1]);
  replaced.kind = 'EvidencePlaneObserved';
  replaced.resources[0].uid = 'replacement-uid';
  assert.equal(resumeResourceAnomalyCount([...records, replaced]), 2);
});

test('A13 reduction proof uses materialized execution IDs and preserves their order', () => {
  const source = [{id: 'execution-03'}, {id: 'execution-01'}, {id: 'execution-02'}];
  assert.equal(preservesExecutionOrder(source, [
    {executionId: 'execution-03'}, {executionId: 'execution-02'},
  ]), true);
  assert.equal(preservesExecutionOrder(source, [
    {executionId: 'execution-02'}, {executionId: 'execution-03'},
  ]), false);
  assert.equal(preservesExecutionOrder(source, [{executionId: 'template-logical-id'}]), false);
});

test('A13 removal proof rejects additions, reordering, and invented nested removals', () => {
  const source = [
    {id: 'one', stages: [{id: 'stage', actions: [{id: 'action', actors: ['a', 'b']}]}]},
    {id: 'two', stages: [{id: 'stage', actions: [{id: 'action', actors: ['a']}]}]},
  ];
  assert.equal(validateRemovalOnlyRelation(source, [{executionId: 'one'}]), true);
  assert.equal(validateRemovalOnlyRelation(source, [{executionId: 'two'}, {executionId: 'one'}]), false);
  assert.equal(validateRemovalOnlyRelation(source, [{executionId: 'one', removedTargets: ['stage/action/c']}]), false);
  assert.equal(validateRemovalOnlyRelation(source, [{executionId: 'invented'}]), false);
});
