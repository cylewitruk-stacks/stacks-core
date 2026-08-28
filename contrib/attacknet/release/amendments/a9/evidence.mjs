#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {validateA9CandidateBuild} from './qualification/candidate-build.mjs';
import {A9_CHECK_IDS, validateA9Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');

export const A9_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a9-live-evidence/v1';
export const A9_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A9_STORAGE_MINIMUM_AVAILABLE_BYTES = 8 * 1024 * 1024 * 1024;
export const A9_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
  candidateBuild: 'candidate-build.json',
  storagePreflight: 'storage-preflight.json',
  liveQualification: 'live-qualification.json',
  negativeControl: 'negative-control.json',
  primaryRun: 'primary/run.json',
  primaryCampaign: 'primary/campaign.json',
  primaryViews: 'primary/node-views.json',
  flashReceipt: 'primary/flash-receipt.json',
  replayRun: 'replay/run.json',
  replayCampaign: 'replay/campaign.json',
  replayViews: 'replay/node-views.json',
  forensicManifest: 'primary/incident/manifest.json',
  cleanTeardown: 'clean-teardown.json',
});
export const A9_ASSERTIONS = Object.freeze([
  'qualified-tree-and-candidate-images',
  'kubelet-root-and-image-storage-capacity-proven-before-build-and-network',
  'offline-race-envtest-helm-and-product-checks-pass',
  'stale-precondition-mutates-no-bitcoin-branch',
  'two-block-suffix-is-replaced-by-three-block-higher-work-branch',
  'stacks-miner-signer-and-follower-recover-on-the-replacement-branch',
  'burnchain-policy-is-restored-before-a-subsequent-flash',
  'subsequent-fast-block-flash-is-applied-and-observed',
  'same-seed-fresh-network-replay-reproduces-schedule-and-outcome-class',
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
function snapshot(value, tree, kind, label) {
  qualified(value, tree, label);
  if (value.schemaVersion !== 'stacks-attacknet-resource-snapshot/v1'
    || value.scope !== 'single-resource-status' || value.resource?.kind !== kind) {
    fail(`${label} is not a ${kind} status snapshot`);
  }
  immutable(value.resourceDigest, `${label}.resourceDigest`);
  return value.resource;
}
function action(campaign) {
  const stages = campaign.status?.stages ?? [];
  if (stages.length !== 1 || stages[0].actions?.length !== 1) fail('reorg campaign must contain exactly one observed action');
  return stages[0].actions[0];
}
function effect(actionStatus) {
  if (actionStatus.effectResults?.length !== 1) fail('reorg action must contain exactly one effect result');
  return actionStatus.effectResults[0];
}
function chainwork(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]+$/.test(value)) fail(`${label} chainwork is invalid`);
  return BigInt(`0x${value}`);
}
function provesBranch(headers, parent, label) {
  let previous = parent;
  for (const [index, header] of (headers ?? []).entries()) {
    if (header?.height !== previous?.height + 1 || header?.previousblockhash !== previous?.hash
      || chainwork(header?.chainwork, `${label}[${index}]`) <= chainwork(previous?.chainwork, `${label} parent`)) {
      return false;
    }
    previous = header;
  }
  return true;
}

/** Validate the exact-tree whole-product Attacknet result required by A9. */
export function validateA9AttacknetCheck(value, tree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== tree || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0
    || value.suites.some(suite => typeof suite?.name !== 'string' || suite.name.length === 0
      || !Number.isSafeInteger(suite.tests) || suite.tests < 1
      || suite.passed !== suite.tests || suite.failed !== 0)) {
    fail('Attacknet check is not a complete qualified-tree pass');
  }
  return value;
}

/** Validate the exact-tree, fully equipped Hacknet result required by A9. */
export function validateA9HacknetCheck(value, tree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== tree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A9 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

/** Validate capacity evidence at both expensive A9 deployment boundaries. */
export function validateA9StoragePreflight(value, tree) {
  qualified(value, tree, 'storage preflight');
  if (value.schemaVersion !== 'stacks-attacknet-a9-storage-preflight/v1'
    || value.minimumAvailableBytes !== A9_STORAGE_MINIMUM_AVAILABLE_BYTES
    || !Number.isFinite(Date.parse(value.recordedAt ?? ''))
    || !Array.isArray(value.checks) || value.checks.length !== 2) {
    fail('A9 storage preflight is incomplete');
  }
  const expected = ['before-build', 'before-network'];
  for (const [index, check] of value.checks.entries()) {
    if (check.phase !== expected[index] || check.exitCode !== 0 || check.ok !== true
      || check.schemaVersion !== 1 || check.source !== 'kubelet-stats-summary'
      || check.minimumAvailableBytes !== A9_STORAGE_MINIMUM_AVAILABLE_BYTES
      || !Number.isFinite(Date.parse(check.observedAt ?? ''))
      || !Array.isArray(check.nodes) || check.nodes.length !== 3
      || new Set(check.nodes.map(node => node.name)).size !== 3
      || check.nodes.some(node => node.ok !== true
        || node.rootFilesystem?.availableBytes < A9_STORAGE_MINIMUM_AVAILABLE_BYTES
        || node.imageFilesystem?.availableBytes < A9_STORAGE_MINIMUM_AVAILABLE_BYTES)) {
      fail(`A9 ${expected[index]} storage preflight did not prove sufficient capacity`);
    }
  }
  return value;
}

/** Validate the exact original and replacement branch proof retained by a campaign. */
export function validateA9Campaign(value, tree, expectedNetwork) {
  const campaign = snapshot(value, tree, 'FaultCampaign', `${expectedNetwork} campaign`);
  const observed = action(campaign);
  const result = effect(observed);
  const evidence = result.evidence;
  if (campaign.spec?.networkRef !== expectedNetwork || campaign.status?.phase !== 'Passed'
    || campaign.status?.cleanup?.allRecovered !== true || observed.phase !== 'Completed'
    || typeof campaign.status?.admission?.networkUid !== 'string'
    || campaign.status.admission.networkUid.length === 0
    || !/^sha256:[0-9a-f]{64}$/.test(campaign.status.admission.networkInventory?.digest ?? '')
    || observed.mutation?.kind !== 'BurnchainReorgWorker'
    || result.assertion !== 'BurnchainReorgProven' || result.outcome !== 'Proven'
    || !evidence?.canonicalProven || evidence.schemaVersion !== 'attacknet-burnchain-reorg-result/v1'
    || evidence.preparedDigest !== observed.actualInjection?.preparedDigest
    || evidence.originalBranch?.length !== 2 || evidence.replacementBranch?.length !== 3
    || evidence.original?.blocks + 1 !== evidence.final?.blocks
    || evidence.final?.bestblockhash !== evidence.replacementBranch[2]?.hash
    || evidence.original?.bestblockhash !== evidence.originalBranch[1]?.hash
    || evidence.forkParent?.height !== evidence.original.blocks - 2
    || !provesBranch(evidence.originalBranch, evidence.forkParent, 'original branch')
    || !provesBranch(evidence.replacementBranch, evidence.forkParent, 'replacement branch')
    || evidence.original?.chainwork !== evidence.originalBranch[1]?.chainwork
    || evidence.final?.chainwork !== evidence.replacementBranch[2]?.chainwork
    || new Set([...evidence.originalBranch, ...evidence.replacementBranch].map(block => block.hash)).size !== 5
    || chainwork(evidence.final?.chainwork, 'final') <= chainwork(evidence.original?.chainwork, 'original')) {
    fail(`${expectedNetwork} campaign does not prove the requested two-for-three reorganization`);
  }
  const methods = evidence.receipts?.map(receipt => receipt.method);
  if (methods?.length !== 5 || methods[0] !== 'invalidateblock'
    || methods.at(-1) !== 'reconsiderblock'
    || methods.filter(method => method === 'generatetoaddress').length !== 3
    || !evidence.receipts.every((receipt, index) => receipt.sequence === index + 1 && receipt.outcome === 'acknowledged')) {
    fail(`${expectedNetwork} campaign RPC receipts are incomplete or out of order`);
  }
  if (!observed.recoveryResults?.some(item => item.assertion === 'BurnchainPolicyRestored' && item.outcome === 'Proven')) {
    fail(`${expectedNetwork} campaign does not prove policy restoration`);
  }
  return value;
}

function assertionSets(run) {
  const sets = run.status?.protocolAssertions ?? {};
  return ['baseline', 'during', 'recovery'].map(name => [name, sets[name]]);
}

/** Validate a terminal run and independently observed recovery gates. */
export function validateA9Run(value, tree, expectedNetwork) {
  const run = snapshot(value, tree, 'AttacknetRun', `${expectedNetwork} run`);
  if (run.spec?.networkRef !== expectedNetwork || run.status?.phase !== 'Passed'
    || run.status?.cleanup?.completed !== true || run.status?.budgetUsage?.burnchainFaults !== 1) {
    fail(`${expectedNetwork} run did not pass its one admitted burnchain campaign`);
  }
  for (const [name, set] of assertionSets(run)) {
    if (set?.outcome !== 'Proven' || !Array.isArray(set.results) || set.results.length === 0
      || set.results.some(result => result.outcome !== 'Proven')) {
      fail(`${expectedNetwork} ${name} protocol assertions were not all proven`);
    }
  }
  return value;
}

/** Validate the prepare/approve stale-tip negative control and zero mutation. */
export function validateA9NegativeControl(value, tree) {
  qualified(value, tree, 'negative control');
  const status = value.workerStatus;
  if (value.schemaVersion !== 'stacks-attacknet-a9-stale-precondition/v1'
    || value.outcome !== 'Passed' || status?.phase !== 'Failed'
    || !String(status.failure).includes('precondition is stale')
    || status.prepared || status.result?.canonicalProven === true
    || (status.result?.receipts?.length ?? 0) !== 0
    || value.before.bestblockhash !== status.result?.original?.bestblockhash
    || value.intervening.bestblockhash !== value.after.bestblockhash
    || value.intervening.blocks !== value.before.blocks + 1
    || value.workerPodUID === '' || !Number.isFinite(Date.parse(value.observedAt ?? ''))) {
    fail('stale-precondition negative control does not prove zero reorg mutation');
  }
  return value;
}

/** Validate a policy-restored, bounded flash receipt following the reorg. */
export function validateA9Flash(value, tree) {
  qualified(value, tree, 'flash receipt');
  if (value.schemaVersion !== 'stacks-attacknet-a9-flash-receipt/v1'
    || value.flash?.id !== 'a9-after-reorg-flash' || value.flash.blocks !== 5
    || value.flash.interval !== '1s' || value.policyBefore?.spec?.paused === true
    || value.policyAfter?.status?.phase !== 'Ready'
    || value.policyAfter.status.appliedFlashId !== value.flash.id
    || value.policyAfter.status.observedHeight < value.policyBefore.status.observedHeight + value.flash.blocks
    || value.actorViews?.observations?.some(actor => actor.burnBlockHeight < value.policyAfter.status.observedHeight)
    || value.actorViews?.observations?.length !== 3) {
    fail('subsequent bounded flash was not applied and observed after policy restoration');
  }
  return value;
}

/** Validate identity-bound Stacks actor views of the replacement branch. */
export function validateA9Views(value, tree, expectedNetwork, replacementTip) {
  qualified(value, tree, `${expectedNetwork} actor views`);
  if (value.schemaVersion !== 'stacks-attacknet-a9-node-views/v1'
    || value.network?.name !== expectedNetwork || !value.network.uid
    || !/^sha256:[0-9a-f]{64}$/.test(value.network.inventoryDigest ?? '')
    || value.replacementTip !== replacementTip
    || value.replacementHeader?.hash !== replacementTip
    || !Number.isSafeInteger(value.replacementHeader?.confirmations)
    || value.replacementHeader.confirmations < 1
    || !Number.isSafeInteger(value.bitcoin?.blocks) || !value.bitcoin?.bestblockhash
    || value.observations?.length !== 3) {
    fail(`${expectedNetwork} actor views are incomplete or observe the wrong Bitcoin branch`);
  }
  const actors = new Set();
  for (const observation of value.observations) {
    if (!['miner-1', 'signer-node-1', 'follower-1'].includes(observation.actor)
      || actors.has(observation.actor) || !observation.podUID
      || !/^sha256:[0-9a-f]{64}$/.test(observation.runtimeImageID ?? '')
      || !Number.isSafeInteger(observation.burnBlockHeight)
      || observation.burnBlockHeight !== value.bitcoin.blocks
      || !Number.isSafeInteger(observation.stacksTipHeight)
      || observation.stacksTipHeight < 1 || observation.evidenceClass !== 'actor_self_reported') {
      fail(`${expectedNetwork} contains an incomplete actor observation`);
    }
    actors.add(observation.actor);
  }
  return value;
}

/** Validate one complete content-addressed incident bundle. */
export function validateA9Incident(path) {
  const manifest = load(path, 'incident manifest');
  if (manifest.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || (manifest.errors !== undefined && (!Array.isArray(manifest.errors) || manifest.errors.length !== 0))
    || (manifest.omissions !== undefined && (!Array.isArray(manifest.omissions) || manifest.omissions.length !== 0))
    || !Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
    fail('forensic incident bundle is incomplete');
  }
  const root = dirname(path);
  for (const artifact of manifest.artifacts) {
    const file = resolve(root, artifact.path);
    if (relative(root, file).startsWith('..') || !statSync(file).isFile()
      || statSync(file).size !== artifact.bytes || digestFile(file) !== artifact.sha256) {
      fail(`forensic incident artifact ${artifact.path} is not bound`);
    }
  }
  return manifest;
}

function walkFiles(root) {
  const files = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) files.push(path);
      else fail(`evidence tree contains unsupported entry ${relative(root, path)}`);
    }
  };
  visit(root);
  return files;
}

function artifact(path, archiveEntry) {
  return {path, archiveEntry, digest: digestFile(path), size: statSync(path).size};
}

/** Suppress macOS AppleDouble members that are not part of the evidence tree. */
export function portableArchiveEnvironment(environment = process.env) {
  return {...environment, COPYFILE_DISABLE: '1'};
}

/** Validate all A9 live artifacts before they are sealed. */
export function validateA9LiveQualification(root, tree) {
  const at = name => join(root, A9_ARTIFACTS[name]);
  const verification = validateA9Verification(load(at('verification'), 'verification'), tree);
  validateA9HacknetCheck(load(at('hacknetCheck'), 'Hacknet check'), tree);
  validateA9AttacknetCheck(load(at('attacknetCheck'), 'Attacknet check'), tree);
  validateA9CandidateBuild(load(at('candidateBuild'), 'candidate build'), tree);
  validateA9StoragePreflight(load(at('storagePreflight'), 'storage preflight'), tree);
  const negative = validateA9NegativeControl(load(at('negativeControl'), 'negative control'), tree);
  const primaryCampaign = validateA9Campaign(load(at('primaryCampaign'), 'primary campaign'), tree, 'a9-qualification');
  const primaryRun = validateA9Run(load(at('primaryRun'), 'primary run'), tree, 'a9-qualification');
  const primaryEffect = effect(action(primaryCampaign.resource)).evidence;
  validateA9Views(load(at('primaryViews'), 'primary views'), tree, 'a9-qualification', primaryEffect.final.bestblockhash);
  validateA9Flash(load(at('flashReceipt'), 'flash receipt'), tree);
  const replayCampaign = validateA9Campaign(load(at('replayCampaign'), 'replay campaign'), tree, 'a9-replay');
  const replayRun = validateA9Run(load(at('replayRun'), 'replay run'), tree, 'a9-replay');
  const replayEffect = effect(action(replayCampaign.resource)).evidence;
  validateA9Views(load(at('replayViews'), 'replay views'), tree, 'a9-replay', replayEffect.final.bestblockhash);
  if (primaryRun.resource.spec.seed !== replayRun.resource.spec.seed
    || replayRun.resource.spec.replay?.sourceRunRef !== primaryRun.resource.metadata.name
    || replayRun.resource.spec.replay?.descriptorDigest !== primaryRun.resource.status.scheduleRef?.digest
    || replayRun.resource.status.scheduleSummary?.replay !== true
    || primaryCampaign.resource.status.phase !== replayCampaign.resource.status.phase
    || primaryEffect.original.bestblockhash === replayEffect.original.bestblockhash
    || primaryCampaign.resource.status.admission.networkUid === replayCampaign.resource.status.admission.networkUid) {
    fail('fresh-network replay does not preserve schedule/outcome while producing an independent branch identity');
  }
  validateA9Incident(at('forensicManifest'));
  const teardown = qualified(load(at('cleanTeardown'), 'clean teardown'), tree, 'clean teardown');
  if (teardown.completed !== true || Object.values(teardown.remainingCounts ?? {}).some(count => count !== 0)) {
    fail('A9 final teardown is incomplete');
  }
  const qualification = qualified(load(at('liveQualification'), 'live qualification'), tree, 'live qualification');
  if (qualification.schemaVersion !== 'stacks-attacknet-a9-live-qualification/v1'
    || qualification.outcome !== 'Passed' || qualification.architecture !== 'arm64'
    || qualification.kindNodes !== 3 || qualification.negativeControlDigest !== digestFile(at('negativeControl'))
    || qualification.storagePreflightDigest !== digestFile(at('storagePreflight'))
    || qualification.primaryCampaignDigest !== digestFile(at('primaryCampaign'))
    || qualification.replayCampaignDigest !== digestFile(at('replayCampaign'))) {
    fail('A9 live qualification receipt is incomplete');
  }
  return {verification, negative, primaryCampaign, replayCampaign, qualification};
}

/** Assemble a portable, content-addressed A9 evidence archive and summary. */
export function assembleA9Evidence({inputDirectory, outputDirectory, qualifiedTree}) {
  const input = resolve(inputDirectory);
  validateA9LiveQualification(input, qualifiedTree);
  const output = resolve(outputDirectory);
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const staging = join(output, '.staging');
  mkdirSync(staging, {recursive: true});
  const artifactEntries = {};
  for (const [key, path] of Object.entries(A9_ARTIFACTS)) {
    const destination = join(staging, path);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, path), destination);
    artifactEntries[key] = artifact(destination, path);
  }
  // Incident descendants are evidence even though only its manifest is a named artifact.
  const incidentSource = dirname(join(input, A9_ARTIFACTS.forensicManifest));
  for (const source of walkFiles(incidentSource)) {
    const entry = join('primary/incident', relative(incidentSource, source));
    if (entry === A9_ARTIFACTS.forensicManifest) continue;
    const destination = join(staging, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const entries = walkFiles(staging).map(path => ({
    path: relative(staging, path), digest: digestFile(path), size: statSync(path).size,
  }));
  const index = {schema: A9_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
  copyFileSync(indexPath, join(staging, 'archive-index.json'));
  const archivePath = join(output, `archive/phase-2-live-evidence-${qualifiedTree.slice(0, 12)}.tar.gz`);
  execFileSync('tar', ['-czf', archivePath, '-C', staging, '.'], {
    env: portableArchiveEnvironment(),
  });
  rmSync(staging, {recursive: true, force: true});
  const assertions = A9_ASSERTIONS.map(id => ({id, status: 'passed'}));
  const artifacts = {};
  for (const [key, value] of Object.entries(artifactEntries)) {
    const finalPath = join(output, value.archiveEntry);
    mkdirSync(dirname(finalPath), {recursive: true});
    copyFileSync(join(input, value.archiveEntry), finalPath);
    artifacts[key] = artifact(finalPath, value.archiveEntry);
  }
  // Preserve the complete incident tree beside the named evidence locators.
  const incidentOutput = dirname(join(output, A9_ARTIFACTS.forensicManifest));
  rmSync(incidentOutput, {recursive: true, force: true});
  mkdirSync(dirname(incidentOutput), {recursive: true});
  for (const source of walkFiles(incidentSource)) {
    const destination = join(incidentOutput, relative(incidentSource, source));
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const summary = {
    schema: A9_SUMMARY_SCHEMA, qualifiedTree, generatedAt: new Date().toISOString(),
    assertions, artifacts,
    archive: {
      path: archivePath, digest: digestFile(archivePath), location: 'local-review-bundle',
      indexPath, indexDigest: digestFile(indexPath), indexEntry: 'archive-index.json',
    },
  };
  const summaryPath = join(output, 'live-summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  // Validate the archive while the staged qualified tree is still unsigned.
  // Packet assembly must not be the first consumer to discover an unindexed or
  // platform-specific tar member after hardware signing.
  validatePortableLiveSummary(summary, {commitPending: false}, {
    root: repositoryRoot,
    schema: A9_SUMMARY_SCHEMA,
    checkpoint: 'A9 evidence assembly',
    requiredArtifacts: Object.keys(A9_ARTIFACTS),
    requiredAssertions: A9_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: qualifiedTree, description: 'qualified Git tree'},
  });
  return {summary, summaryPath};
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const input = value('--input='); const output = value('--output='); const tree = value('--qualified-tree=');
  if (!input || !output || !tree) fail('usage: evidence.mjs --input=DIR --output=DIR --qualified-tree=TREE');
  const result = assembleA9Evidence({inputDirectory: input, outputDirectory: output, qualifiedTree: tree});
  process.stdout.write(`${JSON.stringify({summary: result.summaryPath, archive: result.summary.archive.path})}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
