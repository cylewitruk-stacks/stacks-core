import {createHash} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
export const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
export const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
export const namespace = 'hacknet-system';

export function fail(message) { throw new Error(message); }
export function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}
export function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
export function digestFile(path) { return digestBytes(readFileSync(path)); }
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
export function canonicalDigest(value) { return digestBytes(JSON.stringify(canonical(value))); }
export function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true, mode: 0o700});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}
export function loadJSON(path) { return JSON.parse(readFileSync(path, 'utf8')); }

export function command(executable, arguments_, {
  cwd = repositoryRoot, env = process.env, input, allowFailure = false,
  timeout = 1_800_000,
} = {}) {
  const result = spawnSync(executable, arguments_, {
    cwd, env, input, encoding: 'utf8', timeout, maxBuffer: 256 << 20,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result;
}
export function parsed(executable, arguments_, options) {
  const result = command(executable, arguments_, options);
  try { return JSON.parse(result.stdout); }
  catch (error) {
    fail(`${executable} ${arguments_.join(' ')} returned invalid JSON: ${error.message}\n${result.stdout}`);
  }
}
export function kubectl(arguments_, options) {
  return command(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, options);
}
export function kubectlJSON(arguments_) {
  return JSON.parse(kubectl([...arguments_, '-o', 'json']).stdout);
}
export function optional(kind, name) {
  const result = kubectl(['-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json']);
  return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
}
export function waitFor(label, read, predicate, seconds = 1_800) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = read();
    if (predicate(last)) return last;
    sleep(1_000);
  }
  fail(`${label} did not converge in ${seconds}s: ${JSON.stringify(last?.status ?? last)}`);
}
export function listItems(kind, read = kubectlJSON) {
  // Kubernetes list responses are always JSON, including an empty `items`
  // array. `--ignore-not-found` suppresses that empty document for zero-item
  // lists, which would make a clean qualification scope look malformed.
  const value = read(['-n', namespace, 'get', kind]);
  if (!Array.isArray(value?.items)) fail(`kubectl list ${kind} did not return an item array`);
  return value.items;
}
export function a13Resource(item) {
  return String(item.metadata?.labels?.['testing.stacks.org/fuzz-session'] ?? '').startsWith('a13-')
    || String(item.metadata?.name ?? '').startsWith('a13-');
}
export function fuzzSessionReservation(item) {
  return item.metadata?.annotations?.['testing.stacks.org/fuzz-session'] != null
    || item.metadata?.labels?.['testing.stacks.org/fuzz-session'] != null;
}
export function scopedCountsFromLists(resources, retainedNetworkNames = []) {
  const required = ['networks', 'runs', 'faultCampaigns', 'upgradeCampaigns', 'policies',
    'persistentVolumeClaims', 'leases', 'jobs'];
  if (required.some(key => !Array.isArray(resources?.[key]))) {
    fail('A13 teardown requires a successful complete Kubernetes list for every scoped resource kind');
  }
  const networks = resources.networks.filter(a13Resource);
  const networkNames = new Set([
    ...networks.map(item => item.metadata?.name).filter(Boolean), ...retainedNetworkNames,
  ]);
  const belongsToNetwork = item => {
    const name = item.metadata?.labels?.['testing.stacks.org/network'];
    return networkNames.has(name) || String(name ?? '').startsWith('a13-');
  };
  const isA13 = item => a13Resource(item) || belongsToNetwork(item);
  return {
    networks: networks.length,
    runs: resources.runs.filter(isA13).length,
    faultCampaigns: resources.faultCampaigns.filter(isA13).length,
    upgradeCampaigns: resources.upgradeCampaigns.filter(isA13).length,
    policies: resources.policies.filter(isA13).length,
    persistentVolumeClaims: resources.persistentVolumeClaims.filter(belongsToNetwork).length,
    leases: resources.leases.filter(item =>
      item.metadata?.name === 'attacknet-fuzz-session' || isA13(item)).length,
    reservationJobs: resources.jobs.filter(fuzzSessionReservation).length,
    reservationPVCs: resources.persistentVolumeClaims.filter(fuzzSessionReservation).length,
  };
}
export function scopedCounts(retainedNetworkNames = []) {
  return scopedCountsFromLists({
    networks: listItems('stacksnetworks.testing.stacks.org'),
    runs: listItems('attacknetruns.testing.stacks.org'),
    faultCampaigns: listItems('faultcampaigns.testing.stacks.org'),
    upgradeCampaigns: listItems('upgradecampaigns.testing.stacks.org'),
    policies: listItems('burnchainpolicies.testing.stacks.org'),
    persistentVolumeClaims: listItems('persistentvolumeclaims'),
    leases: listItems('leases.coordination.k8s.io'),
    jobs: listItems('jobs.batch'),
  }, retainedNetworkNames);
}
export function cleanCounts(value) { return Object.values(value).every(count_ => count_ === 0); }

export function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  const localKind = context.startsWith('kind-')
    || context === 'docker-desktop' && nodes.every(node => node.metadata?.name?.startsWith('desktop-'));
  if (!localKind || nodes.length !== 3 || nodes.some(node =>
    node.status?.nodeInfo?.architecture !== 'arm64'
      || !node.status?.conditions?.some(condition =>
        condition.type === 'Ready' && condition.status === 'True'))) {
    fail('A13 requires a local three-node Ready arm64 kind cluster');
  }
  return {provider: 'kind', context, architecture: 'arm64', nodes: nodes.map(node => node.metadata.name).sort()};
}

export function prepareOutput(outputDirectory, artifacts) {
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true, mode: 0o700});
  const retained = new Set(['candidate.patch', 'verification.json', 'attacknet-result.json', 'hacknet-result.json']);
  for (const path of [...Object.values(artifacts), '.execution']) {
    if (retained.has(path)) continue;
    if (existsSync(join(output, path))) fail(`refusing to overwrite A13 evidence ${path}`);
  }
  return output;
}

export function buildCLI(executionDirectory) {
  const attacknet = join(executionDirectory, 'attacknet');
  command('go', ['build', '-o', attacknet, './cmd/attacknet'], {
    cwd: operatorDirectory, timeout: 900_000,
  });
  return attacknet;
}

export function dockerImage(ref) {
  const result = command('docker', ['image', 'inspect', ref], {allowFailure: true});
  if (result.status !== 0) fail(`required previously-qualified actor image is missing: ${ref}`);
  const value = JSON.parse(result.stdout)[0];
  if (!/^sha256:[0-9a-f]{64}$/.test(value?.Id ?? '')) fail(`Docker image ${ref} lacks an immutable ID`);
  return value;
}

export function installQualifiedProduct(attacknet, qualifiedTree, cluster) {
  const build = parsed(attacknet, ['image', 'build', '--repo-root', repositoryRoot], {timeout: 3_600_000});
  const actorRefs = [
    'stacks-core-attacknet:a11-candidate', 'stacks-core-attacknet:a11-stable',
    'stacks-signer-adversarial:r1a12', 'bitcoin/bitcoin:25.2', 'busybox:1.36.1',
  ];
  const actors = actorRefs.map(ref => ({ref, id: dockerImage(ref).Id}));
  const refs = [...build.images.map(image => image.ref), ...actorRefs];
  const load = parsed(attacknet, ['image', 'load', '--mode', 'require', ...refs], {timeout: 2_400_000});
  const install = parsed(attacknet, ['install', 'local', '--chart-dir', chartDirectory,
    '--namespace', namespace, '--release', 'hacknet', '--kind-image-load', 'require',
    '--force-crd-conflicts', '--recover-failed-release'], {timeout: 1_200_000});
  return {qualifiedTree, build, load, install, actors,
    loadedNodes: [...cluster.nodes], recordedAt: new Date().toISOString()};
}

export function submitPath(attacknet, path) {
  return parsed(attacknet, ['submit', '--file', path, '--namespace', namespace, '--output', 'json']);
}
export function submitObject(attacknet, value, directory, label) {
  const path = join(directory, `${label}.json`);
  writeJSON(path, value);
  return submitPath(attacknet, path);
}
export function normalizedResource(attacknet, path) {
  return parsed(attacknet, ['validate', '--file', path, '--namespace', namespace, '--output', 'json']);
}
export function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', '--timeout', '15m', kind, name],
    {allowFailure: true, timeout: 960_000});
  const text = `${result.stderr}${result.stdout}`.toLowerCase();
  if (result.status !== 0 && !text.includes('not found')) {
    fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
  }
}

export function planDescriptor(attacknet, plan, directory, label) {
  const path = join(directory, `${label}.plan.json`);
  const descriptorPath = join(directory, `${label}.descriptor.json`);
  writeJSON(path, plan);
  command(attacknet, ['fuzz', 'plan', '--file', path, '--output', descriptorPath,
    '--namespace', namespace]);
  return {path, descriptorPath, descriptor: loadJSON(descriptorPath), bytes: readFileSync(descriptorPath)};
}
export function runFuzz(attacknet, descriptorPath, corpusRoot, options = {}) {
  return command(attacknet, ['fuzz', 'run', '--descriptor', descriptorPath, '--corpus', corpusRoot], {
    ...options, timeout: options.timeout ?? 14_400_000,
  });
}
export function resumeFuzz(attacknet, sessionDigest, corpusRoot, options = {}) {
  return command(attacknet, ['fuzz', 'resume', '--session', sessionDigest, '--corpus', corpusRoot], {
    ...options, timeout: options.timeout ?? 14_400_000,
  });
}

export function sessionJournal(corpusRoot, sessionDigest) {
  const root = join(corpusRoot, 'sessions', sessionDigest.slice(7), 'journal');
  if (!existsSync(root)) return [];
  return readdirSync(root).filter(name => name.endsWith('.json')).sort()
    .map(name => loadJSON(join(root, name)));
}
export function sessionReport(corpusRoot, sessionDigest) {
  const pointer = loadJSON(join(corpusRoot, 'reports', `${sessionDigest.slice(7)}.json`));
  return loadObject(corpusRoot, pointer.report);
}
export function loadObject(corpusRoot, reference) {
  return loadJSON(join(corpusRoot, 'objects', 'sha256', reference.digest.slice(7, 9), reference.digest.slice(7)));
}
export function corpusEntries(corpusRoot) {
  const root = join(corpusRoot, 'entries');
  if (!existsSync(root)) return [];
  const result = [];
  for (const fingerprint of readdirSync(root).sort()) {
    for (const name of readdirSync(join(root, fingerprint)).filter(value => value.endsWith('.json')).sort()) {
      result.push(loadJSON(join(root, fingerprint, name)));
    }
  }
  return result;
}
export function lastRecord(records, kind, attemptID = undefined) {
  return [...records].reverse().find(record => record.kind === kind
    && (attemptID == null || record.attemptId === attemptID));
}
export function identityDigest(records, attemptID = 'source') {
  const resources = [];
  for (const kind of ['PoliciesObserved', 'TemplatesObserved', 'EvidencePlaneObserved', 'NetworkObserved', 'RunObserved']) {
    const record = lastRecord(records, kind, attemptID);
    if (record) resources.push(...record.resources);
  }
  resources.sort((left, right) => {
    const a = `${left.kind}/${left.name}`;
    const b = `${right.kind}/${right.name}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  return canonicalDigest(resources);
}

export function startFuzz(attacknet, arguments_, {cwd = repositoryRoot, env = process.env} = {}) {
  const child = spawn(attacknet, arguments_, {cwd, env, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const completion = new Promise(resolve_ => child.on('close', (code, signal) =>
    resolve_({code, signal, stdout, stderr})));
  return {child, completion};
}
export async function interruptAt({attacknet, arguments_, corpusRoot, sessionDigest, label, predicate,
  timeoutSeconds = 1_800, pollMilliseconds = 200}) {
  const running = startFuzz(attacknet, arguments_);
  const deadline = Date.now() + timeoutSeconds * 1000;
  let records = [];
  while (Date.now() < deadline) {
    records = sessionJournal(corpusRoot, sessionDigest);
    if (predicate(records)) break;
    if (running.child.exitCode != null) {
      const result = await running.completion;
      fail(`${label} process exited before interruption point: ${result.stderr || result.stdout}`);
    }
    await new Promise(resolve_ => setTimeout(resolve_, pollMilliseconds));
  }
  if (!predicate(records)) fail(`${label} interruption point was not reached`);
  running.child.kill('SIGKILL');
  const result = await running.completion;
  if (result.signal !== 'SIGKILL' && result.code === 0) fail(`${label} was not interrupted`);
  return {records, result};
}
export function breakCorpusLock(attacknet, corpusRoot, reason) {
  const record = loadJSON(join(corpusRoot, '.writer.lock'));
  parsed(attacknet, ['fuzz', 'lock', 'break', '--corpus', corpusRoot,
    '--expected-owner', record.owner, '--expected-process-id', String(record.processId),
    '--expected-acquired-at', record.acquiredAt, '--reason', reason]);
  return record;
}
export function breakSessionLease(attacknet, corpusRoot, reason) {
  const status = parsed(attacknet, [
    'fuzz', 'lease', 'status', '--corpus', corpusRoot, '--namespace', namespace,
  ]);
  parsed(attacknet, ['fuzz', 'lease', 'break', '--corpus', corpusRoot, '--namespace', namespace,
    '--expected-uid', status.lease.uid, '--expected-resource-version', status.lease.resourceVersion,
    '--expected-holder', status.holder, '--reason', reason]);
  return status;
}

export function removeTree(path) { rmSync(path, {recursive: true, force: true}); }
export function requireFile(path) {
  if (!statSync(path).isFile()) fail(`required file is missing: ${path}`);
}
