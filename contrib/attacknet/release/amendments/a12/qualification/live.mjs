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
  A12_ARTIFACTS, validateA12CandidateBuild, validateA12Campaign, validateA12EgressControl,
  validateA12ForgeryControl, validateA12LiveQualification, validateA12LiveResult,
  validateA12Network, validateA12NormalImageControl, validateA12ObserverReplacementControl,
  validateA12PolicyDriftControl, validateA12Run, validateA12Teardown,
} from '../evidence.mjs';
import {
  isMainModule, isMaterializedSource, materializeQualifiedTree, runMaterializedEntrypoint,
} from '../qualified-source.mjs';
import {requireA12QualifiedTree} from '../verify.mjs';

const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
const credentialFixture = join(repositoryRoot,
  'contrib/attacknet/test/fixtures/equivalence/v1alpha1/topology/multi-actor-probes.input.json');
const signerPatchPath = join(repositoryRoot,
  'contrib/attacknet/test/fixtures/adversaries/deterministic-signer.patch');
const namespace = 'hacknet-system';
const terminal = new Set(['Passed', 'Failed', 'Inconclusive', 'Paused']);
const marker = 'ATTACKNET TEST POLICY ACTIVE';
const policyDigests = Object.freeze({
  below: 'sha256:0988a0e12d98e1f89bbe3213c89373ca103a075bad8240e1420ed83d4eda883e',
  quorum: 'sha256:dcc3dd791d9335a3dffa4eea63194a8a0c21f568466f3bbc593454f8470f2137',
});
const scenarios = Object.freeze({
  normal: {network: 'a12-normal-control', policy: 'a12-normal-control'},
  primary: {network: 'a12-adversarial', policy: 'a12-adversarial'},
  replay: {network: 'a12-replay', policy: 'a12-replay'},
});

function fail(message) { throw new Error(message); }
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}
function sleep(milliseconds) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds); }
function command(executable, arguments_, {
  cwd = repositoryRoot, env = process.env, input, allowFailure = false, timeout = 180_000,
} = {}) {
  const result = spawnSync(executable, arguments_, {
    cwd, env, input, encoding: 'utf8', timeout, maxBuffer: 128 << 20,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  }
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
function submitPath(attacknet, path) {
  return parsed(attacknet, ['submit', '--file', path, '--namespace', namespace, '--output', 'json']);
}
function submitObject(attacknet, value, directory, label) {
  const path = join(directory, `${label}.json`);
  writeJSON(path, value);
  return submitPath(attacknet, path);
}
function normalizedResource(attacknet, path) {
  return parsed(attacknet, ['validate', '--file', path, '--namespace', namespace, '--output', 'json']);
}
function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', '--timeout', '10m', kind, name],
    {allowFailure: true, timeout: 660_000});
  if (result.status !== 0 && !`${result.stderr}${result.stdout}`.toLowerCase().includes('not found')) {
    fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
  }
}
function networkReady(name) {
  return waitFor(`StacksNetwork ${name}`, () => optional('stacksnetwork.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.inventoryReady === true
      && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.inventoryDigest ?? ''), 1_500);
}
function policyReady(name) {
  return waitFor(`BurnchainPolicy ${name}`, () => optional('burnchainpolicy.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.appliedPolicyDigest ?? ''), 1_200);
}
function waitRun(name) {
  return waitFor(`AttacknetRun ${name}`, () => optional('attacknetrun.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
      && (value.status.phase !== 'Passed' || value.status.cleanup?.completed === true), 1_800);
}
function waitCampaign(name, phases = terminal) {
  return waitFor(`FaultCampaign ${name}`, () => optional('faultcampaign.testing.stacks.org', name), value =>
    phases.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation, 600);
}
function snapshotResource(attacknet, kind, name, path, tree) {
  mkdirSync(dirname(path), {recursive: true});
  command(attacknet, ['evidence', 'snapshot', '--namespace', namespace, '--output', path, kind, name]);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  writeJSON(path, {qualifiedTree: tree, ...value});
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Prepare a private output directory without adopting prior evidence. */
export function prepareQualificationOutput(outputDirectory) {
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true, mode: 0o700});
  for (const path of [...Object.values(A12_ARTIFACTS), '.execution']) {
    if (['candidate.patch', 'verification.json', 'attacknet-result.json', 'hacknet-result.json'].includes(path)) continue;
    try { statSync(join(output, path)); fail(`refusing to overwrite A12 evidence ${path}`); }
    catch (error) { if (!String(error.message).includes('ENOENT')) throw error; }
  }
}

/** Copy immutable qualification manifests into the private execution root. */
export function stageQualificationManifests(executionDirectory) {
  const directory = join(resolve(executionDirectory), 'manifests');
  mkdirSync(directory, {recursive: true, mode: 0o700});
  for (const name of readdirSync(qualificationDirectory).filter(value => value.endsWith('.yaml'))) {
    writeFileSync(join(directory, name), readFileSync(join(qualificationDirectory, name)), {mode: 0o600});
  }
  return directory;
}

/** Derive ephemeral credentials from the sealed multi-signer fixture. */
export function stageQualificationInputs(executionDirectory) {
  const fixture = JSON.parse(readFileSync(credentialFixture, 'utf8'));
  const actors = new Map((fixture?.spec?.actors ?? []).map(actor => [actor?.name, actor]));
  const file = (actor, key) => actors.get(actor)?.config?.files?.[key];
  const environment = (actor, key) => actors.get(actor)?.env?.find(item => item?.name === key)?.value;
  const miner = file('miner-1', 'config.toml')
    ?.replaceAll('${SERVICE:follower-2}', '${SERVICE:follower-1}')
    .replace('epoch_name = "4.0"\nstart_height = 245', 'epoch_name = "4.0"\nstart_height = 1000005');
  const signerConfigs = ['signer-1', 'signer-2', 'signer-3'].map(name => file(name, 'signer.toml'));
  const privateKeys = environment('stacker', 'STACKING_KEYS');
  const addresses = environment('stacker', 'STACKING_ADDRESSES');
  if (![miner, ...signerConfigs, privateKeys, addresses].every(value => typeof value === 'string' && value.length > 0)
    || miner.includes('${SERVICE:follower-2}') || !miner.includes('start_height = 1000005')) {
    fail('sealed multi-signer fixture does not satisfy the A12 credential contract');
  }
  const secret = (name, stringData) => ({
    apiVersion: 'v1', kind: 'Secret', metadata: {name, namespace}, type: 'Opaque', stringData,
  });
  const resources = {apiVersion: 'v1', kind: 'List', items: [
    secret('a12-miner-config', {'config.toml': miner}),
    ...signerConfigs.map((config, index) => secret(`a12-signer-${index + 1}`, {'signer.toml': config})),
    secret('a12-stacker-credentials', {'private-keys': privateKeys, addresses}),
  ]};
  const path = join(resolve(executionDirectory), 'inputs.json');
  writeJSON(path, resources);
  return {path, secretNames: resources.items.map(item => item.metadata.name)};
}

function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  const localKind = context.startsWith('kind-')
    || context === 'docker-desktop' && nodes.every(node => node.metadata?.name?.startsWith('desktop-'));
  if (!localKind || nodes.length !== 3
    || nodes.some(node => node.status?.nodeInfo?.architecture !== 'arm64'
      || !node.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'))) {
    fail('A12 requires three Ready arm64 kind nodes');
  }
  return {provider: 'kind', context, architecture: 'arm64', nodes: nodes.map(node => node.metadata.name).sort()};
}
function dockerImage(ref) {
  const value = JSON.parse(command('docker', ['image', 'inspect', ref]).stdout)[0];
  if (!/^sha256:[0-9a-f]{64}$/.test(value?.Id ?? '')) fail(`Docker image ${ref} lacks an immutable ID`);
  return value;
}
function binaryContains(ref, text, executionDirectory) {
  const container = command('docker', ['create', ref]).stdout.trim();
  const path = join(executionDirectory, `${ref.replaceAll(/[^a-zA-Z0-9]/g, '-')}-stacks-signer`);
  try {
    command('docker', ['cp', `${container}:/bin/stacks-signer`, path]);
    return command('grep', ['-a', '-q', text, path], {allowFailure: true}).status === 0;
  } finally {
    command('docker', ['rm', '-f', container], {allowFailure: true});
    rmSync(path, {force: true});
  }
}
function buildImages(attacknet, tree, executionDirectory, cluster) {
  const controlPlane = parsed(attacknet, ['image', 'build', '--repo-root', repositoryRoot], {timeout: 3_600_000});
  const normalRef = 'stacks-core-attacknet:a12-normal';
  const adversarialRef = 'stacks-signer-adversarial:r1a12';
  command('docker', ['build', '--tag', normalRef,
    '--file', join(repositoryRoot, 'contrib/attacknet/images/cli/Dockerfile'),
    '--build-arg', 'ATTACKNET_CARGO_FEATURES=monitoring_prom,slog_json',
    '--build-arg', `GIT_COMMIT=${tree}`, repositoryRoot], {timeout: 10_800_000});
  const patched = materializeQualifiedTree(repositoryRoot, tree);
  try {
    command('git', ['apply', '--check', signerPatchPath], {cwd: patched.sourceRoot});
    command('git', ['apply', signerPatchPath], {cwd: patched.sourceRoot});
    command('docker', ['build', '--tag', adversarialRef,
      '--file', join(patched.sourceRoot, 'contrib/attacknet/images/cli/Dockerfile'),
      '--build-arg', 'ATTACKNET_CARGO_FEATURES=monitoring_prom,slog_json,testing',
      '--build-arg', `GIT_COMMIT=${tree}`, patched.sourceRoot], {timeout: 10_800_000});
  } finally { patched.cleanup(); }
  const normal = dockerImage(normalRef);
  const adversarial = dockerImage(adversarialRef);
  const normalContains = binaryContains(normalRef, marker, executionDirectory);
  const adversarialContains = binaryContains(adversarialRef, marker, executionDirectory);
  if (normalContains || !adversarialContains
    || normal.Config?.Labels?.['org.stacks.attacknet.cargo-features']?.includes('testing')
    || !adversarial.Config?.Labels?.['org.stacks.attacknet.cargo-features']?.split(',').includes('testing')) {
    fail('normal and adversarial signer images do not preserve the testing-feature boundary');
  }
  const refs = [...controlPlane.images.map(image => image.ref), normalRef, adversarialRef];
  const load = parsed(attacknet, ['image', 'load', '--mode', 'require', ...refs], {timeout: 1_800_000});
  const install = parsed(attacknet, ['install', 'local', '--chart-dir', chartDirectory,
    '--namespace', namespace, '--release', 'hacknet', '--kind-image-load', 'require',
    '--force-crd-conflicts'], {timeout: 1_200_000});
  const byRef = new Map([
    ...controlPlane.images.map(image => [image.ref, {name: image.purpose, runtimeImageID: image.id}]),
    [normalRef, {name: 'normal-stacks', runtimeImageID: normal.Id}],
    [adversarialRef, {name: 'adversarial-signer', runtimeImageID: adversarial.Id}],
  ]);
  const images = refs.map(ref => ({...byRef.get(ref), requestedRef: ref, loadedNodes: [...cluster.nodes]}));
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-candidate-build/v1', outcome: 'Passed',
    capturedAt: new Date().toISOString(), cluster, images, controlPlane: {build: controlPlane, load, install},
    signerPatch: {
      feature: 'testing', sourceDigest: digestFile(signerPatchPath), normalImageContainsPatch: normalContains,
      adversarialImageContainsPatch: adversarialContains, normalRuntimeImageID: normal.Id,
      adversarialRuntimeImageID: adversarial.Id,
    },
  };
  return {value, normalRef, adversarialRef,
    probeRef: controlPlane.images.find(image => image.purpose === 'probe')?.ref,
    stackerRef: controlPlane.images.find(image => image.purpose === 'stacker')?.ref};
}

function scenarioResources(attacknet, manifestDirectory, names, images, {normal = false} = {}) {
  const network = normalizedResource(attacknet, join(manifestDirectory, 'network.yaml'));
  network.metadata.name = names.network;
  network.spec.burnchain.policyRef.name = names.policy;
  network.spec.defaults.nodeImage = images.normalRef;
  network.spec.defaults.signerImage = images.normalRef;
  network.spec.enrollment.image = images.stackerRef;
  for (const set of network.spec.signerSets) for (const member of set.members) {
    member.signerImage = normal ? images.normalRef : images.adversarialRef;
    member.adversarial.observer.image = images.probeRef;
  }
  const policy = normalizedResource(attacknet, join(manifestDirectory, 'policy.yaml'));
  policy.metadata.name = names.policy;
  policy.spec.networkRef = names.network;
  return {network, policy};
}
function applyNetwork(attacknet, resources, executionDirectory, label) {
  submitObject(attacknet, resources.policy, executionDirectory, `${label}-policy`);
  submitObject(attacknet, resources.network, executionDirectory, `${label}-network`);
  networkReady(resources.network.metadata.name);
  return policyReady(resources.policy.metadata.name);
}
function assertCampaignTemplate(campaign, expectedPolicyDigest) {
  const faults = campaign?.spec?.stages?.flatMap(stage => stage.faults ?? []) ?? [];
  if (campaign?.spec?.template !== true || campaign.spec.networkRef
    || faults.length < 1
    || faults.some(fault => fault?.fault?.signerBehavior?.policyDigest !== expectedPolicyDigest)) {
    fail(`A12 campaign ${campaign?.metadata?.name ?? '<unnamed>'} is not an inert template bound to ${expectedPolicyDigest}`);
  }
}
function directCampaign(attacknet, path, name, network, executionDirectory,
  expectedPolicyDigest, triggerHeight = 1_000_000) {
  const campaign = normalizedResource(attacknet, path);
  assertCampaignTemplate(campaign, expectedPolicyDigest);
  campaign.metadata.name = name;
  campaign.spec.template = false;
  campaign.spec.networkRef = network;
  campaign.spec.stages[0].trigger = {stacksHeight: triggerHeight};
  submitObject(attacknet, campaign, executionDirectory, name);
  return campaign;
}
function mutationCount() {
  return kubectlJSON(['-n', namespace, 'get', 'pods']).items
    .filter(item => item.metadata?.annotations?.['testing.stacks.org/adversarial-session']).length;
}
function normalImageControl(attacknet, manifestDirectory, executionDirectory, tree, output, images) {
  const resources = scenarioResources(attacknet, manifestDirectory, scenarios.normal, images, {normal: true});
  applyNetwork(attacknet, resources, executionDirectory, 'normal-control');
  const signerSetContinuity = rewardSetReady(scenarios.normal.network);
  const name = 'a12-normal-image-control';
  const before = mutationCount();
  directCampaign(attacknet, join(manifestDirectory, 'below-quorum-campaign.yaml'), name,
    scenarios.normal.network, executionDirectory, policyDigests.below);
  const campaign = waitCampaign(name);
  const after = mutationCount();
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-normal-image-control/v1',
    outcome: campaign.status.phase === 'Failed' && campaign.status.reason === 'ProbeBaselineUnavailable'
      && before === after ? 'Passed' : 'Failed',
    classification: campaign.status.reason, campaignAdmitted: campaign.status.admission != null,
    clusterMutationsBefore: before, clusterMutationsAfter: after,
    signerSetContinuity,
    campaignUID: campaign.metadata.uid, observedAt: new Date().toISOString(),
  };
  validateA12NormalImageControl(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.normalImageControl), value);
  deleteResource(attacknet, 'FaultCampaign', name);
  deleteResource(attacknet, 'BurnchainPolicy', scenarios.normal.policy);
  deleteResource(attacknet, 'StacksNetwork', scenarios.normal.network);
}

function executeIn(actor, script, allowFailure = false, network = scenarios.primary.network) {
  return kubectl(['-n', namespace, 'exec', `${network}-${actor}-0`, '-c', 'actor', '--', 'sh', '-ceu', script],
    {allowFailure, timeout: 30_000});
}
function egressControl(tree, output) {
  const checks = {
    dns: executeIn('signer-1', 'getent hosts a12-adversarial-signer-node-1 >/dev/null', true),
    declaredDependency: executeIn('signer-1', 'curl -sf --max-time 4 http://a12-adversarial-signer-node-1:20443/v2/info >/dev/null', true),
    kubernetesAPI: executeIn('signer-1', 'curl -skf --max-time 3 https://kubernetes.default.svc/version >/dev/null', true),
    undeclaredActor: executeIn('signer-1', 'curl -sf --max-time 3 http://a12-adversarial-follower-1:20443/v2/info >/dev/null', true),
  };
  const policy = kubectlJSON(['-n', namespace, 'get', 'networkpolicy', 'a12-adversarial-signer-1']);
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-egress-control/v1', profile: 'restricted',
    outcome: checks.dns.status === 0 && checks.declaredDependency.status === 0
      && checks.kubernetesAPI.status !== 0 && checks.undeclaredActor.status !== 0 ? 'Passed' : 'Failed',
    networkPolicySpecDigest: policy.metadata.annotations?.['testing.stacks.org/egress-policy-digest'],
    checks: Object.fromEntries(Object.entries(checks).map(([name, result]) => [name, {
      allowed: result.status === 0, diagnosticDigest: digestBytes(Buffer.from(`${result.stdout}\0${result.stderr}`)),
    }])), observedAt: new Date().toISOString(),
  };
  validateA12EgressControl(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.egressControl), value);
}
function signedReport(observer, target, policy, nonce) {
  const body = JSON.stringify({kind: 'signerBehavior', peer: target, port: 'metrics', behavior: 'withhold', nonce});
  const script = `fetch('http://127.0.0.1:18080/v1/probe',{method:'POST',headers:{'content-type':'application/json'},body:${JSON.stringify(body)}}).then(async r=>{const t=await r.text();if(!r.ok)throw new Error(t);process.stdout.write(t)}).catch(e=>{console.error(e);process.exit(1)})`;
  return JSON.parse(kubectl(['-n', namespace, 'exec', `${scenarios.primary.network}-${observer}-0`, '-c', 'actor', '--', 'node', '-e', script], {timeout: 30_000}).stdout);
}
function waitProbe() {
  return waitFor('signed signer observer', () => {
    try { return signedReport('signer-1-observer', 'signer-1', policyDigests.below, '0123456789abcdef0123456789abcdef'); }
    catch { return undefined; }
  }, value => value?.attestation?.signature, 300);
}
function forgeryControl(attacknet, executionDirectory, tree, output) {
  const report = waitProbe();
  const legitimatePath = join(executionDirectory, 'legitimate-signer-report.json');
  writeJSON(legitimatePath, report);
  const baseArgs = ['evidence', 'verify-signer-report', '--file', legitimatePath,
    '--actor', 'signer-1-observer', '--target', 'signer-1', '--policy-digest', policyDigests.below,
    '--nonce', report.nonce, '--key-id', report.attestation.keyId];
  command(attacknet, baseArgs);
  const forged = structuredClone(report);
  forged.attestation.signature = Buffer.alloc(64).toString('base64');
  const forgedPath = join(executionDirectory, 'forged-signer-report.json');
  writeJSON(forgedPath, forged);
  const result = command(attacknet, baseArgs.map(value => value === legitimatePath ? forgedPath : value), {allowFailure: true});
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-forgery-control/v1',
    outcome: result.status !== 0 && `${result.stderr}${result.stdout}`.includes('signature is invalid') ? 'Passed' : 'Failed',
    classification: 'SignatureVerificationFailed', accepted: result.status === 0,
    terminalPassPossible: false, diagnosticDigest: digestBytes(Buffer.from(`${result.stdout}\0${result.stderr}`)),
    observedAt: new Date().toISOString(),
  };
  validateA12ForgeryControl(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.forgeryControl), value);
}
function actorStatus(network, actor) { return network.status.actors.find(value => value.name === actor); }
function policyDriftControl(attacknet, manifestDirectory, executionDirectory, tree, output, originalNetwork) {
  const name = 'a12-policy-drift-control';
  directCampaign(attacknet, join(manifestDirectory, 'below-quorum-campaign.yaml'), name,
    scenarios.primary.network, executionDirectory, policyDigests.below);
  const admitted = waitCampaign(name, new Set(['Admitted']));
  const admittedNetwork = networkReady(scenarios.primary.network);
  const admittedPolicy = actorStatus(admittedNetwork, 'signer-1').adversarialPolicyDigest;
  const changed = structuredClone(originalNetwork);
  changed.spec.signerSets[0].members[0].adversarial.maxEvaluations += 1;
  const before = mutationCount();
  submitObject(attacknet, changed, executionDirectory, 'policy-drift-network');
  const changedNetwork = waitFor('changed adversarial policy', () => networkReady(scenarios.primary.network), value =>
    actorStatus(value, 'signer-1').adversarialPolicyDigest !== admittedPolicy, 600);
  const campaign = waitCampaign(name);
  submitObject(attacknet, originalNetwork, executionDirectory, 'policy-restored-network');
  const restored = waitFor('restored adversarial policy', () => networkReady(scenarios.primary.network), value =>
    actorStatus(value, 'signer-1').adversarialPolicyDigest === admittedPolicy, 600);
  const after = mutationCount();
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-policy-drift-control/v1',
    outcome: ['AdmissionInputChanged', 'TargetIdentityDiverged'].includes(campaign.status.reason)
      && before === after ? 'Passed' : 'Failed', classification: campaign.status.reason,
    clusterMutationsBefore: before, clusterMutationsAfter: after,
    admittedInventoryDigest: admittedNetwork.status.inventoryDigest,
    changedInventoryDigest: changedNetwork.status.inventoryDigest,
    restoredInventoryDigest: restored.status.inventoryDigest,
    admittedPolicyDigest: admittedPolicy,
    changedPolicyDigest: actorStatus(changedNetwork, 'signer-1').adversarialPolicyDigest,
    restoredPolicyDigest: actorStatus(restored, 'signer-1').adversarialPolicyDigest,
    admittedCampaignUID: admitted.metadata.uid, observedAt: new Date().toISOString(),
  };
  validateA12PolicyDriftControl(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.policyDriftControl), value);
  deleteResource(attacknet, 'FaultCampaign', name);
}
function observerReplacementControl(attacknet, manifestDirectory, executionDirectory, tree, output) {
  const name = 'a12-observer-replacement-control';
  directCampaign(attacknet, join(manifestDirectory, 'below-quorum-campaign.yaml'), name,
    scenarios.primary.network, executionDirectory, policyDigests.below);
  waitCampaign(name, new Set(['Admitted']));
  const before = kubectlJSON(['-n', namespace, 'get', 'pod', 'a12-adversarial-signer-1-observer-0']);
  kubectl(['-n', namespace, 'delete', 'pod', before.metadata.name, '--wait=true']);
  const campaign = waitCampaign(name);
  const after = waitFor('replacement observer Pod', () => optional('pod', before.metadata.name), value =>
    value?.metadata?.uid && value.metadata.uid !== before.metadata.uid
      && value.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'), 600);
  networkReady(scenarios.primary.network);
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-observer-replacement-control/v1',
    outcome: ['TargetIdentityDiverged', 'AdmissionInputChanged'].includes(campaign.status.reason)
      && campaign.status.phase !== 'Passed' ? 'Passed' : 'Failed',
    classification: campaign.status.reason, beforePodUID: before.metadata.uid,
    afterPodUID: after.metadata.uid, campaignPhase: campaign.status.phase,
    campaignUID: campaign.metadata.uid, observedAt: new Date().toISOString(),
  };
  validateA12ObserverReplacementControl(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.observerReplacementControl), value);
  deleteResource(attacknet, 'FaultCampaign', name);
}

function normalizedRewardSet(response) {
  const signers = response?.stacker_set?.signers;
  if (!Array.isArray(signers)) return undefined;
  const normalized = signers.map(signer => ({
    signingKey: signer?.signing_key,
    weight: signer?.weight,
  }));
  if (normalized.some(signer => !/^(02|03)[0-9a-f]{64}$/.test(signer.signingKey ?? '')
    || !Number.isSafeInteger(signer.weight) || signer.weight < 1)) return undefined;
  normalized.sort((left, right) => left.signingKey < right.signingKey ? -1 : left.signingKey > right.signingKey ? 1 : 0);
  return {signers: normalized, digest: digestBytes(JSON.stringify(normalized))};
}

/** Prove the canonical reward set is unchanged across the next cycle boundary. */
export function rewardSetContinuity(pox, currentResponse, nextResponse) {
  const cycle = pox?.current_cycle?.id;
  const nextCycle = pox?.next_cycle?.id;
  const current = normalizedRewardSet(currentResponse);
  const next = normalizedRewardSet(nextResponse);
  const ready = Number.isSafeInteger(cycle) && Number.isSafeInteger(nextCycle) && nextCycle === cycle + 1
    && current?.signers.length === 3 && next?.signers.length === 3 && current.digest === next.digest;
  return {
    ready, cycle, nextCycle,
    burnHeight: pox?.current_burnchain_block_height,
    blocksUntilNextCycle: pox?.next_reward_cycle_in,
    currentSignerCount: current?.signers.length ?? 0,
    nextSignerCount: next?.signers.length ?? 0,
    currentDigest: current?.digest ?? '', nextDigest: next?.digest ?? '',
  };
}

function rewardSetReady(network = scenarios.primary.network) {
  return waitFor('continuous three-signer canonical reward set', () => {
    const pox = executeIn('miner-1', 'curl -sf http://127.0.0.1:20443/v2/pox', true, network);
    if (pox.status !== 0) return undefined;
    const poxValue = JSON.parse(pox.stdout);
    const cycle = poxValue?.current_cycle?.id;
    const nextCycle = poxValue?.next_cycle?.id;
    if (!Number.isSafeInteger(cycle) || !Number.isSafeInteger(nextCycle)) return undefined;
    const current = executeIn('miner-1', `curl -sf http://127.0.0.1:20443/v3/stacker_set/${cycle}`, true, network);
    const next = executeIn('miner-1', `curl -sf http://127.0.0.1:20443/v3/stacker_set/${nextCycle}`, true, network);
    if (current.status !== 0 || next.status !== 0) {
      return {ready: false, cycle, nextCycle, currentHTTPStatus: current.status, nextHTTPStatus: next.status};
    }
    return rewardSetContinuity(poxValue, JSON.parse(current.stdout), JSON.parse(next.stdout));
  }, value => value?.ready === true, 1_200);
}
function runScenario(attacknet, manifestDirectory, executionDirectory, tree, output, {
  network, templateName, runName, campaignFile, runFile, prefix, expectedActors, expectedRunPhase, duringOutcome,
  expectedPolicyDigest,
}) {
  const campaign = normalizedResource(attacknet, join(manifestDirectory, campaignFile));
  assertCampaignTemplate(campaign, expectedPolicyDigest);
  campaign.metadata.name = templateName;
  const run = normalizedResource(attacknet, join(manifestDirectory, runFile));
  run.metadata.name = runName;
  run.spec.networkRef = network;
  run.spec.seed = `${run.spec.seed}-${network}`;
  run.spec.campaignCatalog[0].campaignRef = templateName;
  submitObject(attacknet, campaign, executionDirectory, `${prefix}-template`);
  submitObject(attacknet, run, executionDirectory, `${prefix}-run`);
  const observedRun = waitRun(runName);
  const runSnapshot = snapshotResource(attacknet, 'AttacknetRun', runName,
    join(output, A12_ARTIFACTS[`${prefix}Run`]), tree);
  const childName = `${runName}-execution-${run.spec.executions[0].id}`;
  if (!optional('faultcampaign.testing.stacks.org', childName)) {
    fail(`${runName} terminated ${observedRun.status?.phase}/${observedRun.status?.reason} before creating ${childName}: ${observedRun.status?.message ?? ''}`);
  }
  waitCampaign(childName);
  const campaignSnapshot = snapshotResource(attacknet, 'FaultCampaign', childName,
    join(output, A12_ARTIFACTS[`${prefix}Campaign`]), tree);
  validateA12Run(runSnapshot, tree, network, expectedRunPhase, duringOutcome);
  const observedCampaign = validateA12Campaign(campaignSnapshot, tree, expectedActors);
  const effects = observedCampaign.status.stages.flatMap(stage => stage.actions ?? [])
    .flatMap(action => action.effectResults ?? [])
    .map(item => typeof item === 'string' ? JSON.parse(item) : item);
  const policyMatchDeltas = Object.fromEntries(expectedActors.map(actor => [actor,
    effects.find(item => item.actor === actor)?.policyMatches]));
  return {run: observedRun, runSnapshot, campaignSnapshot,
    policyMatchDelta: expectedActors.length === 1 ? policyMatchDeltas[expectedActors[0]] : undefined,
    policyMatchDeltas,
    outcomeClass: duringOutcome === 'Proven' ? 'bounded-progress' : 'required-progress-absent'};
}
function captureIncident(attacknet, network, output) {
  const path = dirname(join(output, A12_ARTIFACTS.forensicManifest));
  command(attacknet, ['evidence', 'incident', '--namespace', namespace, '--output', path, network], {timeout: 600_000});
  const manifest = JSON.parse(readFileSync(join(path, 'manifest.json'), 'utf8'));
  if (manifest.errors?.length || manifest.omissions?.length) fail('A12 incident bundle is incomplete');
}
function count(kind, predicate) {
  const result = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return 0;
  return JSON.parse(result.stdout).items.filter(predicate).length;
}
function scopeResidue(secretNames = []) {
  const networks = new Set(Object.values(scenarios).map(value => value.network));
  const relevant = item => networks.has(item.spec?.networkRef)
    || networks.has(item.metadata?.labels?.['testing.stacks.org/network'])
    || String(item.metadata?.name ?? '').startsWith('a12-');
  return {
    networks: count('stacksnetworks.testing.stacks.org', relevant),
    policies: count('burnchainpolicies.testing.stacks.org', relevant),
    runs: count('attacknetruns.testing.stacks.org', relevant),
    campaigns: count('faultcampaigns.testing.stacks.org', relevant),
    pods: count('pods', relevant), pvcs: count('persistentvolumeclaims', relevant),
    statefulsets: count('statefulsets.apps', relevant), services: count('services', relevant),
    networkpolicies: count('networkpolicies.networking.k8s.io', relevant),
    configmaps: count('configmaps', relevant),
    secrets: count('secrets', item => secretNames.includes(item.metadata.name) || relevant(item)),
  };
}
function clean(counts) { return Object.values(counts).every(value => value === 0); }
function teardown(attacknet, inputs, tree, output) {
  for (const name of ['a12-below-quorum', 'a12-quorum-loss', 'a12-replay-below']) deleteResource(attacknet, 'AttacknetRun', name);
  for (const name of ['a12-below-quorum-template', 'a12-quorum-loss-template', 'a12-replay-template',
    'a12-normal-image-control', 'a12-policy-drift-control', 'a12-observer-replacement-control']) {
    deleteResource(attacknet, 'FaultCampaign', name);
  }
  for (const value of Object.values(scenarios)) {
    deleteResource(attacknet, 'BurnchainPolicy', value.policy);
    deleteResource(attacknet, 'StacksNetwork', value.network);
  }
  kubectl(['delete', '-f', inputs.path, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  const counts = waitFor('A12 clean teardown', () => scopeResidue(inputs.secretNames), clean, 600);
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a12-clean-teardown/v1',
    outcome: clean(counts) ? 'Passed' : 'Failed', counts, recordedAt: new Date().toISOString(),
  };
  validateA12Teardown(value, tree);
  writeJSON(join(output, A12_ARTIFACTS.cleanTeardown), value);
}

/** Qualify deterministic adversarial actors on a fresh three-node arm64 kind environment. */
export function runQualification({qualifiedTree, outputDirectory}) {
  requireA12QualifiedTree(qualifiedTree);
  prepareQualificationOutput(outputDirectory);
  for (const name of ['verification', 'candidateDiff', 'attacknetCheck', 'hacknetCheck']) {
    if (!statSync(join(outputDirectory, A12_ARTIFACTS[name])).isFile()) fail(`offline artifact ${A12_ARTIFACTS[name]} is required`);
  }
  const cluster = clusterProfile();
  const executionDirectory = join(resolve(outputDirectory), '.execution');
  mkdirSync(executionDirectory, {recursive: true, mode: 0o700});
  const manifestDirectory = stageQualificationManifests(executionDirectory);
  const inputs = stageQualificationInputs(executionDirectory);
  const attacknet = join(executionDirectory, 'attacknet');
  command('go', ['build', '-o', attacknet, './cmd/attacknet'], {cwd: operatorDirectory, timeout: 600_000});
  if (!clean(scopeResidue(inputs.secretNames))) fail(`A12 qualification scope is not clean: ${JSON.stringify(scopeResidue(inputs.secretNames))}`);
  const images = buildImages(attacknet, qualifiedTree, executionDirectory, cluster);
  try {
    kubectl(['apply', '-f', inputs.path]);
    normalImageControl(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory, images);

    const primaryResources = scenarioResources(attacknet, manifestDirectory, scenarios.primary, images);
    applyNetwork(attacknet, primaryResources, executionDirectory, 'primary');
    const primaryRewardSet = rewardSetReady(scenarios.primary.network);
    writeJSON(join(outputDirectory, A12_ARTIFACTS.candidateBuild), images.value);
    validateA12CandidateBuild(images.value, qualifiedTree);
    egressControl(qualifiedTree, outputDirectory);
    forgeryControl(attacknet, executionDirectory, qualifiedTree, outputDirectory);
    policyDriftControl(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory, primaryResources.network);
    observerReplacementControl(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory);
    const below = runScenario(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory, {
      network: scenarios.primary.network, templateName: 'a12-below-quorum-template', runName: 'a12-below-quorum',
      campaignFile: 'below-quorum-campaign.yaml', runFile: 'below-quorum-run.yaml', prefix: 'below',
      expectedActors: ['signer-1'], expectedRunPhase: 'Passed', duringOutcome: 'Proven',
      expectedPolicyDigest: policyDigests.below,
    });
    const belowNetwork = snapshotResource(attacknet, 'StacksNetwork', scenarios.primary.network,
      join(outputDirectory, A12_ARTIFACTS.belowNetwork), qualifiedTree);
    validateA12Network(belowNetwork, qualifiedTree, scenarios.primary.network);
    const quorum = runScenario(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory, {
      network: scenarios.primary.network, templateName: 'a12-quorum-loss-template', runName: 'a12-quorum-loss',
      campaignFile: 'quorum-loss-campaign.yaml', runFile: 'quorum-loss-run.yaml', prefix: 'quorum',
      expectedActors: ['signer-2', 'signer-3'], expectedRunPhase: 'Failed', duringOutcome: 'Violated',
      expectedPolicyDigest: policyDigests.quorum,
    });
    const quorumNetwork = snapshotResource(attacknet, 'StacksNetwork', scenarios.primary.network,
      join(outputDirectory, A12_ARTIFACTS.quorumNetwork), qualifiedTree);
    validateA12Network(quorumNetwork, qualifiedTree, scenarios.primary.network);
    captureIncident(attacknet, scenarios.primary.network, outputDirectory);
    deleteResource(attacknet, 'AttacknetRun', 'a12-below-quorum');
    deleteResource(attacknet, 'AttacknetRun', 'a12-quorum-loss');
    deleteResource(attacknet, 'FaultCampaign', 'a12-below-quorum-template');
    deleteResource(attacknet, 'FaultCampaign', 'a12-quorum-loss-template');
    deleteResource(attacknet, 'BurnchainPolicy', scenarios.primary.policy);
    deleteResource(attacknet, 'StacksNetwork', scenarios.primary.network);

    const replayResources = scenarioResources(attacknet, manifestDirectory, scenarios.replay, images);
    applyNetwork(attacknet, replayResources, executionDirectory, 'replay');
    const replayRewardSet = rewardSetReady(scenarios.replay.network);
    const replay = runScenario(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory, {
      network: scenarios.replay.network, templateName: 'a12-replay-template', runName: 'a12-replay-below',
      campaignFile: 'below-quorum-campaign.yaml', runFile: 'below-quorum-run.yaml', prefix: 'replay',
      expectedActors: ['signer-1'], expectedRunPhase: 'Passed', duringOutcome: 'Proven',
      expectedPolicyDigest: policyDigests.below,
    });
    const replayNetwork = snapshotResource(attacknet, 'StacksNetwork', scenarios.replay.network,
      join(outputDirectory, A12_ARTIFACTS.replayNetwork), qualifiedTree);
    validateA12Network(replayNetwork, qualifiedTree, scenarios.replay.network);
    if (belowNetwork.resource.metadata.uid === replayNetwork.resource.metadata.uid
      || below.policyMatchDelta !== replay.policyMatchDelta) fail('fresh replay did not preserve policy-match count');
    teardown(attacknet, inputs, qualifiedTree, outputDirectory);
    const principal = ['candidateBuild', 'belowRun', 'belowCampaign', 'quorumRun', 'quorumCampaign',
      'replayRun', 'replayCampaign', 'forensicManifest'];
    const live = {
      qualifiedTree, schemaVersion: 'stacks-attacknet-a12-live-qualification/v1', outcome: 'Passed',
      capturedAt: new Date().toISOString(), architecture: cluster.architecture, kindNodes: cluster.nodes,
      context: cluster.context,
      belowQuorum: {runPhase: below.run.status.phase, duringOutcome: 'Proven',
        outcomeClass: below.outcomeClass, policyMatchDelta: below.policyMatchDelta},
      quorumLoss: {runPhase: quorum.run.status.phase, duringOutcome: 'Violated', outcomeClass: quorum.outcomeClass},
      replay: {outcomeClass: replay.outcomeClass, policyMatchDelta: replay.policyMatchDelta},
      rewardSetContinuity: {primary: primaryRewardSet, replay: replayRewardSet},
      artifactDigests: Object.fromEntries(principal.map(key => [key, digestFile(join(outputDirectory, A12_ARTIFACTS[key]))])),
    };
    validateA12LiveResult(live, qualifiedTree);
    writeJSON(join(outputDirectory, A12_ARTIFACTS.liveQualification), live);
    validateA12LiveQualification(outputDirectory, qualifiedTree);
  } catch (error) {
    try { teardown(attacknet, inputs, qualifiedTree, outputDirectory); }
    catch (cleanupError) { error.message += `\nCleanup also failed: ${cleanupError.message}`; }
    throw error;
  }
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const qualifiedTree = value('--qualified-tree=');
  const outputDirectory = value('--output=');
  if (!qualifiedTree || !outputDirectory) fail('usage: live.mjs --qualified-tree=TREE --output=PATH');
  if (!isMaterializedSource(repositoryRoot)) {
    return runMaterializedEntrypoint({repositoryRoot, qualifiedTree,
      script: 'contrib/attacknet/release/amendments/a12/qualification/live.mjs',
      arguments_: [`--qualified-tree=${qualifiedTree}`, `--output=${resolve(outputDirectory)}`]});
  }
  return runQualification({qualifiedTree, outputDirectory: resolve(outputDirectory)});
}

if (isMainModule(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
