#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, join, parse, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {validateA12Verification} from './verify.mjs';

export const A12_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a12-live-evidence/v1';
export const A12_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A12_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
  candidateBuild: 'candidate-build.json',
  normalImageControl: 'controls/normal-image.json',
  policyDriftControl: 'controls/policy-drift.json',
  egressControl: 'controls/egress.json',
  forgeryControl: 'controls/forgery.json',
  observerReplacementControl: 'controls/observer-replacement.json',
  belowNetwork: 'below-quorum/network.json',
  belowRun: 'below-quorum/run.json',
  belowCampaign: 'below-quorum/campaign.json',
  quorumNetwork: 'quorum-loss/network.json',
  quorumRun: 'quorum-loss/run.json',
  quorumCampaign: 'quorum-loss/campaign.json',
  replayNetwork: 'replay/network.json',
  replayRun: 'replay/run.json',
  replayCampaign: 'replay/campaign.json',
  forensicManifest: 'forensics/manifest.json',
  cleanTeardown: 'clean-teardown.json',
  liveQualification: 'live-qualification.json',
});
export const A12_ASSERTIONS = Object.freeze([
  'qualified-tree-and-testing-only-image-provenance',
  'offline-race-envtest-helm-rbac-and-product-checks-pass',
  'normal-image-and-policy-drift-controls-fail-before-mutation',
  'restricted-egress-permits-only-declared-data-plane-dependencies',
  'forged-report-and-observer-replacement-cannot-produce-passed-evidence',
  'below-quorum-policy-match-is-signed-bounded-and-preserves-progress',
  'deliberate-quorum-loss-is-signed-and-cannot-be-reported-healthy',
  'fresh-network-replay-preserves-match-count-and-outcome-class',
  'complete-identity-bound-forensic-bundle',
  'clean-final-teardown',
]);

function fail(message) { throw new Error(message); }
function load(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`${label} is not readable JSON: ${error.message}`); }
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function immutable(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
  return value;
}
function qualified(value, tree, label) {
  if (!value || value.qualifiedTree !== tree) fail(`${label} does not pin the qualified tree`);
  return value;
}
function containsPath(parent, child) { return child === parent || child.startsWith(`${parent}${sep}`); }

/** Refuse evidence destinations that overlap source or unsealed input data. */
export function validateA12EvidenceOutput(inputDirectory, outputDirectory) {
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..');
  if (output === parse(output).root || containsPath(output, repository)
    || containsPath(input, output) || containsPath(output, input)) {
    fail(`A12 evidence output must be isolated from repository and input data: ${output}`);
  }
  return output;
}

/** Validate one complete qualified-tree Attacknet result. */
export function validateA12AttacknetCheck(value, tree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== tree || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0
    || value.suites.some(suite => !Number.isSafeInteger(suite?.tests) || suite.tests < 1
      || suite.passed !== suite.tests || suite.failed !== 0)) {
    fail('Attacknet check is not a complete qualified-tree pass');
  }
  return value;
}

/** Validate one fully equipped qualified-tree Hacknet result. */
export function validateA12HacknetCheck(value, tree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== tree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A12 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

/** Validate source, feature, image, and three-node import provenance. */
export function validateA12CandidateBuild(value, tree) {
  qualified(value, tree, 'candidate build');
  const nodes = value.cluster?.nodes ?? [];
  const images = value.images ?? [];
  const patch = value.signerPatch ?? {};
  if (value.schemaVersion !== 'stacks-attacknet-a12-candidate-build/v1'
    || value.outcome !== 'Passed' || value.cluster?.provider !== 'kind'
    || value.cluster.architecture !== 'arm64' || nodes.length !== 3
    || new Set(nodes).size !== 3 || images.length < 6
    || patch.feature !== 'testing' || patch.normalImageContainsPatch !== false
    || patch.adversarialImageContainsPatch !== true
    || patch.normalRuntimeImageID === patch.adversarialRuntimeImageID) {
    fail('A12 candidate build does not prove the isolated testing signer and three-node cluster');
  }
  immutable(patch.sourceDigest, 'signerPatch.sourceDigest');
  immutable(patch.normalRuntimeImageID, 'signerPatch.normalRuntimeImageID');
  immutable(patch.adversarialRuntimeImageID, 'signerPatch.adversarialRuntimeImageID');
  for (const image of images) {
    immutable(image.runtimeImageID, `${image.name}.runtimeImageID`);
    if (!image.name || !image.requestedRef || new Set(image.loadedNodes ?? []).size !== 3
      || nodes.some(node => !image.loadedNodes.includes(node))) {
      fail(`A12 image ${image.name ?? '<unnamed>'} is not imported on every node`);
    }
  }
  return value;
}

function validRewardSetContinuity(value) {
  return value?.ready === true && Number.isSafeInteger(value.cycle)
    && value.nextCycle === value.cycle + 1 && Number.isSafeInteger(value.burnHeight)
    && Number.isSafeInteger(value.blocksUntilNextCycle) && value.currentSignerCount === 3
    && value.nextSignerCount === 3 && /^sha256:[0-9a-f]{64}$/.test(value.currentDigest ?? '')
    && value.currentDigest === value.nextDigest;
}

/** Validate a normal signer cannot open an attributed behavior campaign. */
export function validateA12NormalImageControl(value, tree) {
  qualified(value, tree, 'normal image control');
  if (value.schemaVersion !== 'stacks-attacknet-a12-normal-image-control/v1'
    || value.outcome !== 'Passed' || value.classification !== 'ProbeBaselineUnavailable'
    || value.campaignAdmitted !== false || value.clusterMutationsBefore !== value.clusterMutationsAfter
    || !validRewardSetContinuity(value.signerSetContinuity)) {
    fail('A12 normal image control did not fail closed before mutation');
  }
  return value;
}

/** Validate policy drift prevents injection and the original identity is restored. */
export function validateA12PolicyDriftControl(value, tree) {
  qualified(value, tree, 'policy drift control');
  if (value.schemaVersion !== 'stacks-attacknet-a12-policy-drift-control/v1'
    || value.outcome !== 'Passed' || !['AdmissionInputChanged', 'TargetIdentityDiverged'].includes(value.classification)
    || value.clusterMutationsBefore !== value.clusterMutationsAfter
    || !immutable(value.admittedInventoryDigest, 'policyDrift.admittedInventoryDigest')
    || !immutable(value.changedInventoryDigest, 'policyDrift.changedInventoryDigest')
    || value.admittedInventoryDigest === value.changedInventoryDigest
    || !immutable(value.restoredInventoryDigest, 'policyDrift.restoredInventoryDigest')
    || !immutable(value.admittedPolicyDigest, 'policyDrift.admittedPolicyDigest')
    || !immutable(value.changedPolicyDigest, 'policyDrift.changedPolicyDigest')
    || value.admittedPolicyDigest === value.changedPolicyDigest
    || value.restoredPolicyDigest !== value.admittedPolicyDigest) {
    fail('A12 policy drift control did not preserve a zero-mutation identity barrier');
  }
  return value;
}

/** Validate restricted actors can reach declared peers but not cluster control surfaces. */
export function validateA12EgressControl(value, tree) {
  qualified(value, tree, 'egress control');
  const checks = value.checks ?? {};
  if (value.schemaVersion !== 'stacks-attacknet-a12-egress-control/v1'
    || value.outcome !== 'Passed' || value.profile !== 'restricted'
    || checks.dns?.allowed !== true || checks.declaredDependency?.allowed !== true
    || checks.kubernetesAPI?.allowed !== false || checks.undeclaredActor?.allowed !== false
    || !immutable(value.networkPolicySpecDigest, 'egress.networkPolicySpecDigest')) {
    fail('A12 egress control does not prove the restricted allowlist and denials');
  }
  return value;
}

/** Validate invalid signatures are rejected before observations become evidence. */
export function validateA12ForgeryControl(value, tree) {
  qualified(value, tree, 'forgery control');
  if (value.schemaVersion !== 'stacks-attacknet-a12-forgery-control/v1'
    || value.outcome !== 'Passed' || value.classification !== 'SignatureVerificationFailed'
    || value.accepted !== false || value.terminalPassPossible !== false) {
    fail('A12 forgery control did not reject the signed-report substitution');
  }
  return value;
}

/** Validate observer replacement invalidates an in-flight evidence window. */
export function validateA12ObserverReplacementControl(value, tree) {
  qualified(value, tree, 'observer replacement control');
  if (value.schemaVersion !== 'stacks-attacknet-a12-observer-replacement-control/v1'
    || value.outcome !== 'Passed' || !['TargetIdentityDiverged', 'AdmissionInputChanged'].includes(value.classification)
    || !value.beforePodUID || !value.afterPodUID || value.beforePodUID === value.afterPodUID
    || value.campaignPhase === 'Passed') {
    fail('A12 observer replacement control allowed stale attribution to pass');
  }
  return value;
}

function snapshot(value, tree, kind, label) {
  qualified(value, tree, label);
  if (value.schemaVersion !== 'stacks-attacknet-resource-snapshot/v1'
    || value.scope !== 'single-resource-status' || value.resource?.kind !== kind) {
    fail(`${label} is not a ${kind} status snapshot`);
  }
  immutable(value.resourceDigest, `${label}.resourceDigest`);
  return value.resource;
}

function actorMap(network) { return new Map((network.status?.actors ?? []).map(actor => [actor.name, actor])); }

/** Validate Ready admitted adversarial identities and their egress policy digests. */
export function validateA12Network(value, tree, expectedName) {
  const network = snapshot(value, tree, 'StacksNetwork', `${expectedName} network`);
  if (network.metadata?.name !== expectedName || network.status?.phase !== 'Ready'
    || network.status.inventoryReady !== true
    || network.status.observedGeneration !== network.metadata.generation
    || !immutable(network.status.inventoryDigest, `${expectedName}.inventoryDigest`)) {
    fail(`${expectedName} is not a Ready admitted network`);
  }
  const actors = actorMap(network);
  for (const signer of ['signer-1', 'signer-2', 'signer-3']) {
    const actor = actors.get(signer);
    const observer = actors.get(`${signer}-observer`);
    if (!actor?.identityReady || !observer?.identityReady
      || !immutable(actor.adversarialPolicyDigest, `${signer}.policyDigest`)
      || observer.adversarialPolicyDigest !== actor.adversarialPolicyDigest
      || actor.adversarialEgressProfile !== 'restricted'
      || observer.adversarialEgressProfile !== 'restricted'
      || !immutable(actor.egressPolicyDigest, `${signer}.egressPolicyDigest`)
      || !immutable(observer.egressPolicyDigest, `${signer}-observer.egressPolicyDigest`)) {
      fail(`${expectedName}/${signer} lacks a matching admitted observer and egress identity`);
    }
  }
  return network;
}

function signedReports(status) {
  return Object.entries(status?.probeArtifacts ?? {})
    .filter(([key, value]) => key.endsWith('SignedJson') && typeof value === 'string')
    .map(([key, value]) => ({key, value: JSON.parse(value)}));
}

function resultOutcomes(action, field) {
  return (action?.[field] ?? []).map(value => typeof value === 'string' ? JSON.parse(value) : value);
}

/** Validate one completed signer-behavior campaign and its signed counter deltas. */
export function validateA12Campaign(value, tree, expectedActors, expectedPhase = 'Passed') {
  const campaign = snapshot(value, tree, 'FaultCampaign', `${expectedActors.join('+')} campaign`);
  const actions = (campaign.status?.stages ?? []).flatMap(stage => stage.actions ?? []);
  const reports = signedReports(campaign.status);
  if (campaign.status?.phase !== expectedPhase || actions.length !== expectedActors.length
    || reports.length !== expectedActors.length * 3
    || !immutable(campaign.status?.admission?.signerSetDigest, 'campaign.signerSetDigest')) {
    fail('A12 campaign lacks its terminal phase, independently attributable actions, canonical signer set, or signed report triplets');
  }
  const seen = new Set();
  for (const actor of expectedActors) {
    const matching = actions.filter(action => resultOutcomes(action, 'effectResults')
      .some(result => result.actor === actor));
    if (matching.length !== 1 || seen.has(matching[0])) {
      fail(`A12 campaign does not preserve one independently attributable action for ${actor}`);
    }
    seen.add(matching[0]);
    const effects = resultOutcomes(matching[0], 'effectResults');
    const recoveries = resultOutcomes(matching[0], 'recoveryResults');
    if (!effects.some(result => result.actor === actor && result.outcome === 'Proven'
      && Number.isSafeInteger(result.policyMatches) && result.policyMatches > 0
      && /^sha256:[0-9a-f]{64}$/.test(result.reportDigest ?? ''))
      || !recoveries.some(result => result.actor === actor && result.outcome === 'Proven')) {
      fail(`A12 campaign does not prove effect and recovery for ${actor}`);
    }
    const actorReports = reports.filter(report => report.key.includes(`/${actor}SignedJson`));
    const keyIDs = new Set(actorReports.map(report => report.value.attestation?.keyId));
    const nonces = new Set(actorReports.map(report => report.value.nonce));
    if (actorReports.length !== 3 || keyIDs.size !== 1 || nonces.size !== 3
      || actorReports.some(report => !report.value.attestation?.signature
        || !Number.isFinite(Date.parse(report.value.observedAt ?? '')))) {
      fail(`A12 campaign signed reports are not identity-stable and nonce-distinct for ${actor}`);
    }
  }
  if (seen.size !== actions.length) fail('A12 campaign contains an unattributed signer-behavior action');
  return campaign;
}

/** Validate the protocol result associated with a signer-behavior campaign. */
export function validateA12Run(value, tree, expectedNetwork, expectedPhase, duringOutcome) {
  const run = snapshot(value, tree, 'AttacknetRun', `${expectedNetwork} run`);
  if (run.spec?.networkRef !== expectedNetwork || run.status?.phase !== expectedPhase
    || run.status?.protocolAssertions?.during?.outcome !== duringOutcome
    || !immutable(run.status?.scheduleSummary?.networkInventory?.digest, 'run.inventoryDigest')
    || !immutable(run.status?.scheduleSummary?.signerSetDigest, 'run.signerSetDigest')
    || run.status?.resolvedCampaigns?.length !== 1) {
    fail(`${expectedNetwork} run does not establish ${expectedPhase}/${duringOutcome}`);
  }
  if (duringOutcome === 'Violated'
    && !(run.status.protocolAssertions.during.results ?? []).some(result => result.reason === 'RequiredProgressAbsent')) {
    fail(`${expectedNetwork} run lacks the required no-progress violation`);
  }
  return run;
}

/** Validate every retained forensic artifact by digest and length. */
export function validateA12Incident(path) {
  const manifest = load(path, 'incident manifest');
  if (manifest.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || manifest.errors?.length || manifest.omissions?.length || !manifest.artifacts?.length) {
    fail('A12 forensic bundle is incomplete');
  }
  const root = dirname(path);
  for (const entry of manifest.artifacts) {
    const candidate = resolve(root, entry.path);
    if (candidate === root || !containsPath(root, candidate)
      || digestFile(candidate) !== entry.sha256 || statSync(candidate).size !== entry.bytes) {
      fail(`forensic artifact ${entry.path} is invalid`);
    }
  }
  return manifest;
}

/** Validate all A12-scoped cluster resources were removed. */
export function validateA12Teardown(value, tree) {
  qualified(value, tree, 'clean teardown');
  if (value.schemaVersion !== 'stacks-attacknet-a12-clean-teardown/v1'
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))
    || !value.counts || Object.values(value.counts).some(count => count !== 0)) {
    fail('A12 teardown is not clean');
  }
  return value;
}

/** Validate the aggregate live result and its principal artifact bindings. */
export function validateA12LiveResult(value, tree) {
  qualified(value, tree, 'live qualification');
  if (value.schemaVersion !== 'stacks-attacknet-a12-live-qualification/v1'
    || value.outcome !== 'Passed' || value.architecture !== 'arm64'
    || value.kindNodes?.length !== 3 || new Set(value.kindNodes).size !== 3
    || value.belowQuorum?.runPhase !== 'Passed' || value.belowQuorum?.duringOutcome !== 'Proven'
    || value.quorumLoss?.runPhase !== 'Failed' || value.quorumLoss?.duringOutcome !== 'Violated'
    || value.replay?.outcomeClass !== value.belowQuorum?.outcomeClass
    || value.replay?.policyMatchDelta !== value.belowQuorum?.policyMatchDelta
    || !Number.isFinite(Date.parse(value.capturedAt ?? ''))) {
    fail('A12 live qualification does not prove bounded health, quorum loss, and replay');
  }
  for (const [name, receipt] of Object.entries(value.rewardSetContinuity ?? {})) {
    if (!['primary', 'replay'].includes(name) || !validRewardSetContinuity(receipt)) {
      fail(`A12 ${name} reward-set continuity receipt is invalid`);
    }
  }
  if (Object.keys(value.rewardSetContinuity ?? {}).sort().join(',') !== 'primary,replay') {
    fail('A12 live qualification lacks primary and replay reward-set continuity');
  }
  const digests = Object.entries(value.artifactDigests ?? {});
  if (digests.length < 8 || digests.some(([name, digest]) => !name || !/^sha256:[0-9a-f]{64}$/.test(digest))) {
    fail('A12 live qualification does not bind its principal evidence');
  }
  return value;
}

/** Validate every A12 claim directly from one evidence directory. */
export function validateA12LiveQualification(directory, tree) {
  const artifact = key => load(join(directory, A12_ARTIFACTS[key]), key);
  validateA12Verification(artifact('verification'), tree);
  validateA12AttacknetCheck(artifact('attacknetCheck'), tree);
  validateA12HacknetCheck(artifact('hacknetCheck'), tree);
  validateA12CandidateBuild(artifact('candidateBuild'), tree);
  validateA12NormalImageControl(artifact('normalImageControl'), tree);
  validateA12PolicyDriftControl(artifact('policyDriftControl'), tree);
  validateA12EgressControl(artifact('egressControl'), tree);
  validateA12ForgeryControl(artifact('forgeryControl'), tree);
  validateA12ObserverReplacementControl(artifact('observerReplacementControl'), tree);
  const belowNetwork = validateA12Network(artifact('belowNetwork'), tree, 'a12-adversarial');
  const belowRun = validateA12Run(artifact('belowRun'), tree, 'a12-adversarial', 'Passed', 'Proven');
  const belowCampaign = validateA12Campaign(artifact('belowCampaign'), tree, ['signer-1']);
  validateA12Network(artifact('quorumNetwork'), tree, 'a12-adversarial');
  validateA12Run(artifact('quorumRun'), tree, 'a12-adversarial', 'Failed', 'Violated');
  validateA12Campaign(artifact('quorumCampaign'), tree, ['signer-2', 'signer-3']);
  const replayNetwork = validateA12Network(artifact('replayNetwork'), tree, 'a12-replay');
  const replayRun = validateA12Run(artifact('replayRun'), tree, 'a12-replay', 'Passed', 'Proven');
  const replayCampaign = validateA12Campaign(artifact('replayCampaign'), tree, ['signer-1']);
  const delta = campaign => {
    const action = campaign.status.stages[0].actions[0];
    return resultOutcomes(action, 'effectResults')[0].policyMatches;
  };
  if (belowNetwork.metadata.uid === replayNetwork.metadata.uid
    || belowRun.spec.seed === replayRun.spec.seed || delta(belowCampaign) !== delta(replayCampaign)) {
    fail('A12 fresh-network replay does not preserve the match count and outcome class');
  }
  validateA12Incident(join(directory, A12_ARTIFACTS.forensicManifest));
  validateA12Teardown(artifact('cleanTeardown'), tree);
  validateA12LiveResult(artifact('liveQualification'), tree);
  return true;
}

function walkFiles(current) {
  const result = [];
  for (const entry of readdirSync(current, {withFileTypes: true})) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) result.push(...walkFiles(path));
    else if (entry.isFile()) result.push(path);
  }
  return result.sort();
}
function artifact(path, archiveEntry) { return {path, archiveEntry, digest: digestFile(path)}; }
function portableArchiveEnvironment() { return {...process.env, COPYFILE_DISABLE: '1', GZIP: '-n'}; }

/** Copy, index, archive, and summarize a complete A12 qualification bundle. */
export function assembleA12Evidence({inputDirectory, outputDirectory, qualifiedTree}) {
  const input = resolve(inputDirectory);
  validateA12LiveQualification(input, qualifiedTree);
  const output = validateA12EvidenceOutput(input, outputDirectory);
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const staging = join(output, '.staging');
  mkdirSync(staging, {recursive: true});
  const artifactEntries = {};
  for (const [key, path] of Object.entries(A12_ARTIFACTS)) {
    const destination = join(staging, path);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, path), destination);
    artifactEntries[key] = artifact(destination, path);
  }
  const forensicSource = dirname(join(input, A12_ARTIFACTS.forensicManifest));
  for (const source of walkFiles(forensicSource)) {
    const entry = join('forensics', relative(forensicSource, source)).split(sep).join('/');
    if (entry === A12_ARTIFACTS.forensicManifest) continue;
    const destination = join(staging, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const entries = walkFiles(staging).map(path => ({
    path: relative(staging, path).split(sep).join('/'), digest: digestFile(path), size: statSync(path).size,
  }));
  const index = {schema: A12_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
  copyFileSync(indexPath, join(staging, 'archive-index.json'));
  const archivePath = join(output, `archive/phase-2-live-evidence-${qualifiedTree.slice(0, 12)}.tar.gz`);
  execFileSync('tar', ['-czf', archivePath, '-C', staging, '.'], {env: portableArchiveEnvironment()});
  rmSync(staging, {recursive: true, force: true});
  const artifacts = {};
  for (const [key, value] of Object.entries(artifactEntries)) {
    const finalPath = join(output, value.archiveEntry);
    mkdirSync(dirname(finalPath), {recursive: true});
    copyFileSync(join(input, value.archiveEntry), finalPath);
    artifacts[key] = artifact(finalPath, value.archiveEntry);
  }
  const forensicOutput = dirname(join(output, A12_ARTIFACTS.forensicManifest));
  rmSync(forensicOutput, {recursive: true, force: true});
  for (const source of walkFiles(forensicSource)) {
    const destination = join(forensicOutput, relative(forensicSource, source));
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const summary = {
    schema: A12_SUMMARY_SCHEMA, qualifiedTree, generatedAt: new Date().toISOString(),
    assertions: A12_ASSERTIONS.map(id => ({id, status: 'passed'})), artifacts,
    archive: {
      path: archivePath, digest: digestFile(archivePath), location: 'local-review-bundle',
      indexPath, indexDigest: digestFile(indexPath), indexEntry: 'archive-index.json',
    },
  };
  const summaryPath = join(output, 'live-summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  return {summary, summaryPath};
}

/** Validate one portable A12 summary against its signed candidate. */
export function validateA12Summary(summary, candidate, summaryPath, root) {
  validatePortableLiveSummary(summary, candidate, {
    root, schema: A12_SUMMARY_SCHEMA, checkpoint: 'A12',
    requiredArtifacts: Object.keys(A12_ARTIFACTS), requiredAssertions: A12_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: summary.qualifiedTree, description: 'qualified Git tree'},
  });
  const evidenceRoot = dirname(resolve(root, summaryPath));
  if (resolve(root, summary.archive.indexPath) !== resolve(evidenceRoot, summary.archive.indexEntry)
    || resolve(root, summary.archive.path) !== resolve(evidenceRoot, 'archive', basename(summary.archive.path))) {
    fail('A12 archive paths do not resolve from the packet evidence root');
  }
  for (const [key, value] of Object.entries(summary.artifacts)) {
    if (resolve(root, value.path) !== resolve(evidenceRoot, value.archiveEntry)) {
      fail(`${key} does not resolve under the packet evidence root`);
    }
  }
  validateA12LiveQualification(evidenceRoot, summary.qualifiedTree);
  return summary;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const inputDirectory = value('--input=');
  const outputDirectory = value('--output=');
  const qualifiedTree = value('--qualified-tree=');
  if (!inputDirectory || !outputDirectory || !qualifiedTree) {
    fail('usage: evidence.mjs --input=PATH --output=PATH --qualified-tree=TREE');
  }
  const result = assembleA12Evidence({inputDirectory, outputDirectory, qualifiedTree});
  process.stdout.write(`${JSON.stringify(result.summary, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
