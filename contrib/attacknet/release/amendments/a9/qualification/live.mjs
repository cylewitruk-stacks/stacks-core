#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {
  A9_ARTIFACTS, A9_STORAGE_MINIMUM_AVAILABLE_BYTES, validateA9Campaign,
  validateA9Flash, validateA9NegativeControl, validateA9Run,
  validateA9StoragePreflight, validateA9Views,
} from '../evidence.mjs';
import {isMainModule, isMaterializedSource, runMaterializedEntrypoint} from '../qualified-source.mjs';
import {requireA9QualifiedTree} from '../verify.mjs';
import {validateA9CandidateBuild} from './candidate-build.mjs';

const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
const storagePreflightProgram = join(repositoryRoot, 'contrib/attacknet/observability/storage-preflight.sh');
const credentialFixture = join(repositoryRoot,
  'contrib/attacknet/test/fixtures/equivalence/v1alpha1/topology/baseline-probes.input.json');
const namespace = 'hacknet-system';
const terminal = new Set(['Passed', 'Failed', 'Inconclusive', 'Paused']);
const primary = Object.freeze({network: 'a9-qualification', policy: 'a9-qualification', run: 'a9-reorg', child: 'a9-reorg-execution-canonical-reorg'});
const replay = Object.freeze({network: 'a9-replay', policy: 'a9-replay', run: 'a9-reorg-replay', child: 'a9-reorg-replay-execution-canonical-reorg'});

function fail(message) { throw new Error(message); }
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}
function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function command(executable, arguments_, {
  cwd = repositoryRoot, env = process.env, input, allowFailure = false, timeout = 180_000,
} = {}) {
  const result = spawnSync(executable, arguments_, {cwd, env, input, encoding: 'utf8', timeout, maxBuffer: 128 << 20});
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  return result;
}
function parsed(executable, arguments_, options) {
  const result = command(executable, arguments_, options);
  try { return JSON.parse(result.stdout); }
  catch (error) { fail(`${executable} ${arguments_.join(' ')} returned invalid JSON: ${error.message}\n${result.stdout}`); }
}
function kubectl(arguments_, options) { return command(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, options); }
function kubectlJSON(arguments_) { return JSON.parse(kubectl([...arguments_, '-o', 'json']).stdout); }
function optional(kind, name) {
  const result = kubectl(['-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json']);
  return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
}
function waitFor(label, read, predicate, seconds = 600) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = read();
    if (predicate(last)) return last;
    sleep(1000);
  }
  fail(`${label} did not converge in ${seconds}s: ${JSON.stringify(last?.status ?? last)}`);
}
function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  if (!context.startsWith('kind-') || nodes.length !== 3
    || nodes.some(node => node.status?.nodeInfo?.architecture !== 'arm64'
      || !node.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'))) {
    fail('A9 requires three Ready arm64 kind nodes');
  }
  return {provider: 'kind', context, architecture: 'arm64', nodes: 3};
}

function submit(attacknet, manifestDirectory, filename, replacements = {}) {
  let path = join(manifestDirectory, filename);
  let temporary;
  if (Object.keys(replacements).length > 0) {
    temporary = mkdtempSync(join(tmpdir(), 'attacknet-a9-submit-'));
    let contents = readFileSync(path, 'utf8');
    for (const [from, to] of Object.entries(replacements)) contents = contents.replaceAll(from, to);
    if (Object.keys(replacements).some(key => contents.includes(key))) fail(`manifest ${filename} retains an unresolved placeholder`);
    path = join(temporary, filename);
    writeFileSync(path, contents);
  }
  try {
    parsed(attacknet, ['submit', '--file', path, '--namespace', namespace, '--output', 'json']);
  } finally {
    if (temporary) rmSync(temporary, {recursive: true, force: true});
  }
}
function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', '--timeout', '10m', kind, name], {allowFailure: true, timeout: 660_000});
  if (result.status !== 0 && !`${result.stderr}${result.stdout}`.toLowerCase().includes('not found')) {
    fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
  }
}

function networkReady(name) {
  return waitFor(`StacksNetwork ${name}`, () => optional('stacksnetwork.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.inventoryReady === true
      && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.inventoryDigest ?? ''), 900);
}
function policyReady(name, predicate = () => true) {
  return waitFor(`BurnchainPolicy ${name}`, () => optional('burnchainpolicy.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.observedGeneration === value.metadata.generation
      && value.status.observedHeight >= 202 && predicate(value), 600);
}
function patchPolicy(name, patch) {
  kubectl(['-n', namespace, 'patch', 'burnchainpolicy.testing.stacks.org', name,
    '--type=merge', '-p', JSON.stringify({spec: patch})]);
}

function indexed(images) { return new Map(images.map(image => [image.purpose, image])); }

function storageCapacityCheck(phase, executionDirectory) {
  const path = join(executionDirectory, `storage-${phase}.json`);
  const result = command(storagePreflightProgram, [path], {
    allowFailure: true,
    env: {...process.env,
      ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES: String(A9_STORAGE_MINIMUM_AVAILABLE_BYTES)},
  });
  let report;
  try { report = JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { report = {ok: false, error: `storage preflight emitted no readable report: ${error.message}`}; }
  return {phase, exitCode: result.status ?? -1, ...report};
}

function recordStoragePreflight(tree, output, checks) {
  const value = {schemaVersion: 'stacks-attacknet-a9-storage-preflight/v1', qualifiedTree: tree,
    minimumAvailableBytes: A9_STORAGE_MINIMUM_AVAILABLE_BYTES,
    recordedAt: new Date().toISOString(), checks};
  writeJSON(join(output, A9_ARTIFACTS.storagePreflight), value);
  return value;
}

function requireStorageCapacity(phase, tree, output, executionDirectory, checks) {
  checks.push(storageCapacityCheck(phase, executionDirectory));
  const value = recordStoragePreflight(tree, output, checks);
  const check = checks.at(-1);
  if (check.exitCode !== 0 || check.ok !== true) {
    fail(`A9 ${phase} storage preflight failed: ${JSON.stringify(check)}`);
  }
  if (checks.length === 2) validateA9StoragePreflight(value, tree);
}

function buildCandidate(tree, output, executionDirectory) {
  requireA9QualifiedTree(tree);
  const attacknet = join(executionDirectory, 'attacknet');
  command('go', ['build', '-o', attacknet, './cmd/attacknet'], {cwd: operatorDirectory, timeout: 600_000});
  const build = parsed(attacknet, ['image', 'build', '--repo-root', repositoryRoot, '--stacks'], {timeout: 7_200_000});
  const install = parsed(attacknet, ['install', 'local', '--chart-dir', chartDirectory,
    '--namespace', namespace, '--release', 'hacknet', '--kind-image-load', 'require',
    '--force-crd-conflicts'], {timeout: 1_200_000});
  const byPurpose = indexed(build.images);
  const actorImages = ['stacks-core', 'stacker'].map(purpose => ({
    purpose, ref: byPurpose.get(purpose).ref, immutableID: byPurpose.get(purpose).id,
  }));
  const actorImageLoad = parsed(attacknet, ['image', 'load', '--mode', 'require', ...actorImages.map(image => image.ref)], {timeout: 1_200_000});
  const receipt = {schemaVersion: 'stacks-attacknet-a9-candidate-build/v1', qualifiedTree: tree,
    capturedAt: new Date().toISOString(), build, install, actorImages, actorImageLoad,
    runOperatorImageID: byPurpose.get('run-operator').id};
  validateA9CandidateBuild(receipt, tree);
  writeJSON(join(output, A9_ARTIFACTS.candidateBuild), receipt);
  return {attacknet, receipt};
}

function bitcoinPod(network) {
  const value = optional('stacksnetwork.testing.stacks.org', network);
  const actor = value?.status?.actors?.find(item => item.name === 'bitcoin');
  if (!actor?.podName) fail(`${network} has no admitted Bitcoin Pod`);
  return actor.podName;
}
function bitcoinCLI(network, arguments_) {
  return parsed(process.env.ATTACKNET_KUBECTL ?? 'kubectl', ['-n', namespace, 'exec', bitcoinPod(network), '-c', 'actor', '--',
    'bitcoin-cli', '-regtest', '-rpcuser=devnet', '-rpcpassword=devnet', ...arguments_]);
}
function blockchainInfo(network) { return bitcoinCLI(network, ['getblockchaininfo']); }
function blockHeader(network, hash) { return bitcoinCLI(network, ['getblockheader', hash, 'true']); }
function generateBlock(network) {
  const hashes = bitcoinCLI(network, ['-rpcwallet=attacknet-miner-1', 'generatetoaddress', '1', 'n2PEoV6Abxnrpzoqqq1TJT5kw8G2dMPpBd']);
  if (!Array.isArray(hashes) || hashes.length !== 1) fail('negative control did not mine exactly one intervening block');
  return hashes[0];
}
function workerStatus(name) {
  const path = `/api/v1/namespaces/${namespace}/pods/${name}:8090/proxy/status`;
  const result = kubectl(['get', '--raw', path], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return undefined;
  try { return JSON.parse(result.stdout); } catch { return undefined; }
}
function runImage() {
  const deployments = kubectlJSON(['-n', namespace, 'get', 'deployments', '-l', 'app.kubernetes.io/component=run-operator']).items;
  if (deployments.length !== 1) fail('exactly one run operator Deployment is required');
  return deployments[0].spec.template.spec.containers.find(container => container.name === 'run-operator')?.image;
}
function staleWorkerPod(network, preparation) {
  return {apiVersion: 'v1', kind: 'Pod', metadata: {name: 'a9-stale-precondition', namespace,
    labels: {'app.kubernetes.io/component': 'burnchain-reorg-worker-negative-control', 'testing.stacks.org/network': network},
    annotations: {'testing.stacks.org/reorg-preparation': preparation, 'testing.stacks.org/reorg-approval': ''}}, spec: {
    restartPolicy: 'Never', automountServiceAccountToken: false, enableServiceLinks: false,
    securityContext: {runAsNonRoot: true, seccompProfile: {type: 'RuntimeDefault'}},
    containers: [{name: 'worker', image: runImage(), imagePullPolicy: 'IfNotPresent', args: ['burnchain-reorg-worker'],
      env: [
        {name: 'ATTACKNET_REORG_REQUEST_JSON', value: JSON.stringify({depth: 2, replacementBlocks: 3,
          replacementIntervalNanoseconds: 1_000_000_000, wallet: 'attacknet-miner-1', address: 'n2PEoV6Abxnrpzoqqq1TJT5kw8G2dMPpBd'})},
        {name: 'ATTACKNET_REORG_PREPARATION_FILE', value: '/var/run/attacknet-reorg/preparation'},
        {name: 'ATTACKNET_REORG_APPROVAL_FILE', value: '/var/run/attacknet-reorg/approval'},
        {name: 'BITCOIN_RPC_URL', value: `http://${network}-bitcoin:18443`},
        {name: 'BITCOIN_RPC_USERNAME', value: 'devnet'}, {name: 'BITCOIN_RPC_PASSWORD', value: 'devnet'},
      ], ports: [{name: 'status', containerPort: 8090}],
      readinessProbe: {httpGet: {path: '/status', port: 8090}, periodSeconds: 1},
      resources: {requests: {cpu: '10m', memory: '24Mi'}, limits: {cpu: '250m', memory: '128Mi'}},
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true,
        runAsUser: 65532, runAsGroup: 65532, capabilities: {drop: ['ALL']}},
      volumeMounts: [{name: 'approval', mountPath: '/var/run/attacknet-reorg', readOnly: true}, {name: 'tmp', mountPath: '/tmp'}],
    }], volumes: [{name: 'approval', downwardAPI: {items: [
      {path: 'preparation', fieldRef: {apiVersion: 'v1', fieldPath: "metadata.annotations['testing.stacks.org/reorg-preparation']"}},
      {path: 'approval', fieldRef: {apiVersion: 'v1', fieldPath: "metadata.annotations['testing.stacks.org/reorg-approval']"}},
    ]}}, {name: 'tmp', emptyDir: {}}],
  }};
}

function negativeControl(tree, output) {
  patchPolicy(primary.policy, {paused: true});
  const paused = policyReady(primary.policy, value => value.spec.paused === true);
  const preparation = paused.status.appliedPolicyDigest;
  if (!/^sha256:[0-9a-f]{64}$/.test(preparation ?? '')) fail('paused policy has no immutable preparation token');
  kubectl(['apply', '-f', '-'], {input: JSON.stringify(staleWorkerPod(primary.network, preparation))});
  let prepared;
  try {
    const pod = waitFor('stale-precondition worker Pod', () => optional('pod', 'a9-stale-precondition'), value => value?.status?.podIP, 180);
    prepared = waitFor('stale-precondition worker preparation', () => workerStatus('a9-stale-precondition'), value => value?.phase === 'Prepared', 180);
    const before = blockchainInfo(primary.network);
    if (prepared.prepared?.original?.bestblockhash !== before.bestblockhash || prepared.prepared.original.blocks !== before.blocks) {
      fail('negative-control worker prepared a different Bitcoin precondition');
    }
    generateBlock(primary.network);
    const intervening = blockchainInfo(primary.network);
    kubectl(['-n', namespace, 'annotate', 'pod', 'a9-stale-precondition',
      `testing.stacks.org/reorg-approval=${prepared.prepared.digest}`, '--overwrite']);
    const failed = waitFor('stale-precondition worker failure', () => workerStatus('a9-stale-precondition'), value => value?.phase === 'Failed', 180);
    const after = blockchainInfo(primary.network);
    const evidence = {schemaVersion: 'stacks-attacknet-a9-stale-precondition/v1', qualifiedTree: tree,
      outcome: 'Passed', observedAt: new Date().toISOString(), workerPodUID: pod.metadata.uid,
      before, intervening, after, preparedDigest: prepared.prepared.digest, workerStatus: failed};
    validateA9NegativeControl(evidence, tree);
    writeJSON(join(output, A9_ARTIFACTS.negativeControl), evidence);
  } finally {
    kubectl(['-n', namespace, 'delete', 'pod', 'a9-stale-precondition', '--ignore-not-found', '--wait=true'], {allowFailure: true, timeout: 180_000});
    patchPolicy(primary.policy, {paused: false});
    policyReady(primary.policy, value => value.spec.paused === false);
  }
}

function waitRun(name) {
  return waitFor(`AttacknetRun ${name}`, () => optional('attacknetrun.testing.stacks.org', name), value =>
    runIsObservableTerminal(value), 1_200);
}
/** Return once a failed run can be diagnosed, while requiring Passed cleanup proof. */
export function runIsObservableTerminal(value) {
  return terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
    && (value.status.phase !== 'Passed' || value.status.cleanup?.completed === true);
}
function waitCampaign(name) {
  return waitFor(`FaultCampaign ${name}`, () => optional('faultcampaign.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
      && value.status.cleanup?.allRecovered === true, 600);
}
function snapshotResource(attacknet, kind, name, path, tree) {
  mkdirSync(dirname(path), {recursive: true});
  command(attacknet, ['evidence', 'snapshot', '--namespace', namespace, '--output', path, kind, name]);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  writeJSON(path, {qualifiedTree: tree, ...value});
  return JSON.parse(readFileSync(path, 'utf8'));
}

function actorInfo(network, actor) {
  const current = optional('stacksnetwork.testing.stacks.org', network);
  const status = current?.status?.actors?.find(item => item.name === actor);
  if (!status?.podName || !status.podUID || !status.runtimeImageID) fail(`${network}/${actor} has no admitted identity`);
  const result = kubectl(['get', '--raw', `/api/v1/namespaces/${namespace}/pods/${status.podName}:20443/proxy/v2/info`], {allowFailure: true});
  if (result.status !== 0) return undefined;
  let info;
  try { info = JSON.parse(result.stdout); } catch { return undefined; }
  return {actor, podName: status.podName, podUID: status.podUID,
    runtimeImageID: String(status.runtimeImageID).replace(/^.*@(?=sha256:)/, ''),
    burnBlockHeight: info.burn_block_height, burnBlockHash: info.burn_block_hash,
    stacksTipHeight: info.stacks_tip_height, evidenceClass: 'actor_self_reported', raw: info};
}
function captureViews(network, replacementTip, tree) {
  const names = ['miner-1', 'signer-node-1', 'follower-1'];
  const stable = waitFor(`${network} actor branch convergence`, () => {
    const bitcoin = blockchainInfo(network);
    const observations = names.map(actor => actorInfo(network, actor));
    return {bitcoin, observations};
  }, value => value.observations.every(observation => observation
      && observation.burnBlockHeight === value.bitcoin.blocks && observation.stacksTipHeight >= 1), 300);
  const current = optional('stacksnetwork.testing.stacks.org', network);
  const value = {schemaVersion: 'stacks-attacknet-a9-node-views/v1', qualifiedTree: tree,
    observedAt: new Date().toISOString(), network: {name: network, uid: current.metadata.uid,
      inventoryDigest: current.status.inventoryDigest, observedGeneration: current.status.observedGeneration},
    replacementTip, replacementHeader: blockHeader(network, replacementTip),
    bitcoin: stable.bitcoin, observations: stable.observations};
  validateA9Views(value, tree, network, replacementTip);
  return value;
}

function campaignEffect(campaignSnapshot) {
  return campaignSnapshot.resource.status.stages[0].actions[0].effectResults[0].evidence;
}
function runScenario(attacknet, manifestDirectory, descriptor, tree, output, replayDigest = undefined) {
  submit(attacknet, manifestDirectory, descriptor.run === replay.run ? 'run-replay.yaml' : 'run.yaml',
    replayDigest ? {'__SOURCE_SCHEDULE_DIGEST__': replayDigest} : {});
  const run = waitRun(descriptor.run);
  const campaign = waitCampaign(descriptor.child);
  const runSnapshot = snapshotResource(attacknet, 'AttacknetRun', descriptor.run,
    join(output, descriptor === primary ? A9_ARTIFACTS.primaryRun : A9_ARTIFACTS.replayRun), tree);
  const campaignSnapshot = snapshotResource(attacknet, 'FaultCampaign', descriptor.child,
    join(output, descriptor === primary ? A9_ARTIFACTS.primaryCampaign : A9_ARTIFACTS.replayCampaign), tree);
  validateA9Run(runSnapshot, tree, descriptor.network);
  validateA9Campaign(campaignSnapshot, tree, descriptor.network);
  const replacementTip = campaignEffect(campaignSnapshot).final.bestblockhash;
  const views = captureViews(descriptor.network, replacementTip, tree);
  writeJSON(join(output, descriptor === primary ? A9_ARTIFACTS.primaryViews : A9_ARTIFACTS.replayViews), views);
  return {run, campaign, runSnapshot, campaignSnapshot, views, replacementTip};
}

function subsequentFlash(tree, output, reorg) {
  const before = optional('burnchainpolicy.testing.stacks.org', primary.policy);
  const flash = {id: 'a9-after-reorg-flash', blocks: 5, interval: '1s'};
  patchPolicy(primary.policy, {flash});
  const after = policyReady(primary.policy, value => value.status.appliedFlashId === flash.id
    && value.status.observedHeight >= before.status.observedHeight + flash.blocks);
  const views = captureViews(primary.network, reorg.replacementTip, tree);
  const value = {schemaVersion: 'stacks-attacknet-a9-flash-receipt/v1', qualifiedTree: tree,
    observedAt: new Date().toISOString(), flash, policyBefore: before, policyAfter: after, actorViews: views};
  validateA9Flash(value, tree);
  writeJSON(join(output, A9_ARTIFACTS.flashReceipt), value);
  return value;
}

function captureIncident(attacknet, network, output) {
  const path = dirname(join(output, A9_ARTIFACTS.forensicManifest));
  command(attacknet, ['evidence', 'incident', '--namespace', namespace, '--output', path, network], {timeout: 600_000});
  const manifest = JSON.parse(readFileSync(join(path, 'manifest.json'), 'utf8'));
  if (manifest.errors?.length || manifest.omissions?.length) fail('A9 incident bundle is incomplete');
}
function deleteNetwork(attacknet, descriptor) {
  deleteResource(attacknet, 'BurnchainPolicy', descriptor.policy);
  deleteResource(attacknet, 'StacksNetwork', descriptor.network);
}
function count(kind, predicate) {
  const result = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return 0;
  return JSON.parse(result.stdout).items.filter(predicate).length;
}
function cleanTeardown(attacknet, credentialPath, tree, output) {
  for (const descriptor of [replay, primary]) {
    deleteResource(attacknet, 'AttacknetRun', descriptor.run);
    deleteResource(attacknet, 'BurnchainPolicy', descriptor.policy);
    deleteResource(attacknet, 'StacksNetwork', descriptor.network);
  }
  deleteResource(attacknet, 'FaultCampaign', 'a9-reorg-template');
  kubectl(['-n', namespace, 'delete', '-f', credentialPath, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  const relevant = item => ['a9-qualification', 'a9-replay'].includes(item.spec?.networkRef)
    || ['a9-qualification', 'a9-replay'].includes(item.metadata?.labels?.['testing.stacks.org/network']);
  const remainingCounts = {
    networks: count('stacksnetworks.testing.stacks.org', relevant),
    policies: count('burnchainpolicies.testing.stacks.org', relevant),
    runs: count('attacknetruns.testing.stacks.org', relevant),
    campaigns: count('faultcampaigns.testing.stacks.org', relevant),
    pods: count('pods', relevant), pvcs: count('persistentvolumeclaims', relevant),
  };
  const value = {schemaVersion: 'stacks-attacknet-a9-clean-teardown/v1', qualifiedTree: tree,
    completed: Object.values(remainingCounts).every(value_ => value_ === 0), remainingCounts,
    observedAt: new Date().toISOString()};
  writeJSON(join(output, A9_ARTIFACTS.cleanTeardown), value);
  if (!value.completed) fail(`A9 cleanup retained resources: ${JSON.stringify(remainingCounts)}`);
}

function assertCleanScope() {
  const names = [primary.network, replay.network];
  const existing = names.flatMap(name => [
    ['stacksnetwork.testing.stacks.org', name], ['burnchainpolicy.testing.stacks.org', name],
  ]).concat([['faultcampaign.testing.stacks.org', 'a9-reorg-template'],
    ['attacknetrun.testing.stacks.org', primary.run], ['attacknetrun.testing.stacks.org', replay.run],
    ['pod', 'a9-stale-precondition']]).filter(([kind, name]) => optional(kind, name));
  if (existing.length) fail(`A9 qualification scope is not clean: ${existing.map(value => value.join('/')).join(', ')}`);
}
function prepareOutput(output) {
  mkdirSync(output, {recursive: true, mode: 0o700});
  for (const path of Object.values(A9_ARTIFACTS)) {
    if (['candidate.patch', 'verification.json', 'attacknet-result.json', 'hacknet-result.json'].includes(path)) continue;
    try { statSync(join(output, path)); fail(`refusing to overwrite A9 evidence ${path}`); } catch (error) {
      if (!String(error.message).includes('ENOENT')) throw error;
    }
  }
}

/** Copy immutable qualification manifests into one explicitly-lived execution root. */
export function stageQualificationManifests(executionDirectory) {
  const directory = join(resolve(executionDirectory), 'manifests');
  mkdirSync(directory, {mode: 0o700});
  for (const name of readdirSync(qualificationDirectory).filter(value => value.endsWith('.yaml'))) {
    writeFileSync(join(directory, name), readFileSync(join(qualificationDirectory, name)), {mode: 0o600});
  }
  return directory;
}

/** Derive ephemeral Kubernetes Secrets from the already sealed regtest fixture. */
export function stageQualificationCredentials(executionDirectory) {
  const fixture = JSON.parse(readFileSync(credentialFixture, 'utf8'));
  const actors = new Map((fixture?.spec?.actors ?? []).map(actor => [actor?.name, actor]));
  const file = (actor, key) => actors.get(actor)?.config?.files?.[key];
  const environment = (actor, key) => actors.get(actor)?.env?.find(item => item?.name === key)?.value;
  const miner = file('miner-1', 'config.toml');
  const signer = file('signer-1', 'signer.toml');
  const privateKeys = environment('stacker', 'STACKING_KEYS');
  const addresses = environment('stacker', 'STACKING_ADDRESSES');
  if (![miner, signer, privateKeys, addresses].every(value => typeof value === 'string' && value.length > 0)) {
    fail('sealed regtest fixture does not contain the A9 credential contract');
  }
  const secret = (name, stringData) => ({apiVersion: 'v1', kind: 'Secret',
    metadata: {name, namespace}, type: 'Opaque', stringData});
  const value = {apiVersion: 'v1', kind: 'List', items: [
    secret('a9-miner-config', {'config.toml': miner}),
    secret('a9-signer-config', {'signer.toml': signer}),
    secret('a9-stacker-credentials', {'private-keys': privateKeys, addresses}),
  ]};
  const path = join(resolve(executionDirectory), 'credentials.json');
  writeJSON(path, value);
  return path;
}

/** Qualify A9 on a fresh three-node arm64 kind environment. */
export function runQualification({qualifiedTree, outputDirectory}) {
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree ?? '')) fail('qualified tree must be a full Git tree SHA');
  prepareOutput(outputDirectory);
  for (const name of ['verification', 'candidateDiff', 'attacknetCheck', 'hacknetCheck']) {
    if (!statSync(join(outputDirectory, A9_ARTIFACTS[name])).isFile()) fail(`offline artifact ${A9_ARTIFACTS[name]} is required`);
  }
  const cluster = clusterProfile();
  const executionDirectory = join(resolve(outputDirectory), '.execution');
  mkdirSync(executionDirectory, {mode: 0o700});
  const manifestDirectory = stageQualificationManifests(executionDirectory);
  const credentialPath = stageQualificationCredentials(executionDirectory);
  const capacityChecks = [];
  let candidate;
  try {
    requireStorageCapacity('before-build', qualifiedTree, outputDirectory, executionDirectory, capacityChecks);
    candidate = buildCandidate(qualifiedTree, outputDirectory, executionDirectory);
    requireStorageCapacity('before-network', qualifiedTree, outputDirectory, executionDirectory, capacityChecks);
    assertCleanScope();
    kubectl(['apply', '-f', credentialPath]);
    submit(candidate.attacknet, manifestDirectory, 'policy.yaml');
    submit(candidate.attacknet, manifestDirectory, 'network.yaml');
    networkReady(primary.network); policyReady(primary.policy);
    negativeControl(qualifiedTree, outputDirectory);
    submit(candidate.attacknet, manifestDirectory, 'reorg-template.yaml');
    const primaryResult = runScenario(candidate.attacknet, manifestDirectory, primary, qualifiedTree, outputDirectory);
    subsequentFlash(qualifiedTree, outputDirectory, primaryResult);
    captureIncident(candidate.attacknet, primary.network, outputDirectory);
    const sourceDigest = primaryResult.run.status.scheduleRef?.digest;
    if (!/^sha256:[0-9a-f]{64}$/.test(sourceDigest ?? '')) fail('primary run has no immutable resolved schedule');
    deleteNetwork(candidate.attacknet, primary);
    submit(candidate.attacknet, manifestDirectory, 'policy-replay.yaml');
    submit(candidate.attacknet, manifestDirectory, 'network-replay.yaml');
    networkReady(replay.network); policyReady(replay.policy);
    const replayResult = runScenario(candidate.attacknet, manifestDirectory, replay, qualifiedTree, outputDirectory, sourceDigest);
    if (replayResult.run.status.scheduleSummary?.replay !== true) fail('fresh run was not admitted through replay mode');
    cleanTeardown(candidate.attacknet, credentialPath, qualifiedTree, outputDirectory);
    const value = {schemaVersion: 'stacks-attacknet-a9-live-qualification/v1', qualifiedTree,
      outcome: 'Passed', capturedAt: new Date().toISOString(), architecture: cluster.architecture,
      kindNodes: cluster.nodes, context: cluster.context,
      negativeControlDigest: digestFile(join(outputDirectory, A9_ARTIFACTS.negativeControl)),
      storagePreflightDigest: digestFile(join(outputDirectory, A9_ARTIFACTS.storagePreflight)),
      primaryCampaignDigest: digestFile(join(outputDirectory, A9_ARTIFACTS.primaryCampaign)),
      replayCampaignDigest: digestFile(join(outputDirectory, A9_ARTIFACTS.replayCampaign)),
      candidateBuildDigest: digestFile(join(outputDirectory, A9_ARTIFACTS.candidateBuild))};
    writeJSON(join(outputDirectory, A9_ARTIFACTS.liveQualification), value);
    return value;
  } catch (error) {
    writeJSON(join(outputDirectory, 'qualification-failure.json'), {schemaVersion: 'stacks-attacknet-a9-qualification-failure/v1',
      qualifiedTree, failedAt: new Date().toISOString(), message: error.message});
    throw error;
  } finally {
    rmSync(executionDirectory, {recursive: true, force: true});
  }
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const tree = value('--qualified-tree='); const output = value('--output=');
  if (!tree || !output) fail('usage: live.mjs --qualified-tree=TREE --output=DIR');
  if (!isMaterializedSource(repositoryRoot)) {
    runMaterializedEntrypoint({repositoryRoot, qualifiedTree: tree,
      script: 'contrib/attacknet/release/amendments/a9/qualification/live.mjs',
      arguments_: [`--qualified-tree=${tree}`, `--output=${resolve(output)}`]});
    return;
  }
  runQualification({qualifiedTree: tree, outputDirectory: resolve(output)});
}

if (isMainModule(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
