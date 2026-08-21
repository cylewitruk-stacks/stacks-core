#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import net from 'node:net';
import {dirname, join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const attacknetDir = dirname(fileURLToPath(import.meta.url));

export const DOCTOR_CONTRACT = Object.freeze({
  schemaVersion: 1,
  tools: Object.freeze({
    node: Object.freeze({minimum: '20.0.0'}),
    python: Object.freeze({minimum: '3.11.0'}),
    docker: Object.freeze({daemonRequired: true}),
    kubectl: Object.freeze({maximumMinorSkew: 1}),
    helm: Object.freeze({supportedMajors: Object.freeze([3, 4])}),
    kind: Object.freeze({minimum: '0.20.0', required: false}),
  }),
  kubernetes: Object.freeze({supportedMinors: Object.freeze([36])}),
  chaosMesh: Object.freeze({
    supportedVersions: Object.freeze(['2.8.3']),
    requiredCrds: Object.freeze([
      'podchaos.chaos-mesh.org',
      'networkchaos.chaos-mesh.org',
      'dnschaos.chaos-mesh.org',
      'iochaos.chaos-mesh.org',
      'timechaos.chaos-mesh.org',
    ]),
    nativeIoArchitectures: Object.freeze(['amd64']),
    nativeTimeArchitectures: Object.freeze(['amd64']),
  }),
  storage: Object.freeze({minimumAvailableBytes: 8 * 1024 * 1024 * 1024}),
  architectures: Object.freeze({local: Object.freeze(['arm64', 'x64']), cluster: Object.freeze(['arm64', 'amd64'])}),
  images: Object.freeze([
    'stacks-core-attacknet:main',
    'stacks-attacknet-stacker:local',
    'stacks-hacknet-operator:dev',
    'stacks-hacknet-run-operator:dev',
    'stacks-hacknet-io-pressure:dev',
    'stacks-hacknet-probe:dev',
  ]),
  localPorts: Object.freeze([
    Object.freeze({name: 'grafana', address: '127.0.0.1', port: 3000}),
    Object.freeze({name: 'chaos-dashboard', address: '127.0.0.1', port: 2333}),
    Object.freeze({name: 'headlamp', address: '127.0.0.1', port: 8080}),
    Object.freeze({name: 'event-bridge', address: '127.0.0.1', port: 9464}),
  ]),
});

function defaultRunner(command, args) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error ? {code: result.error.code, message: result.error.message} : null,
  };
}

function normalizeResult(result) {
  return {
    status: Number.isInteger(result?.status) ? result.status : null,
    stdout: typeof result?.stdout === 'string' ? result.stdout : '',
    stderr: typeof result?.stderr === 'string' ? result.stderr : '',
    error: result?.error ?? null,
  };
}

async function invoke(runCommand, command, args) {
  try {
    return normalizeResult(await runCommand(command, args));
  } catch (error) {
    return {status: null, stdout: '', stderr: '', error: {code: error?.code, message: String(error?.message ?? error)}};
  }
}

function parseJson(result) {
  if (result.status !== 0) return null;
  try {
    return JSON.parse(result.stdout);
  } catch {
    return null;
  }
}

function parseVersion(value) {
  const match = String(value ?? '').match(/(?:^|[^0-9])v?(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return {major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3] ?? 0), text: `${match[1]}.${match[2]}.${match[3] ?? 0}`};
}

function versionAtLeast(version, minimum) {
  if (!version) return false;
  const expected = parseVersion(minimum);
  for (const key of ['major', 'minor', 'patch']) {
    if (version[key] !== expected[key]) return version[key] > expected[key];
  }
  return true;
}

function commandProblem(result) {
  if (result.error?.code === 'ENOENT') return 'command not found';
  if (result.error?.message) return result.error.message;
  const message = result.stderr.trim().split('\n')[0];
  return message || `command exited ${result.status ?? 'without a status'}`;
}

function check(id, title, required, compatible, message, details = {}) {
  return {
    id,
    title,
    required,
    status: compatible ? 'pass' : (required ? 'fail' : 'warn'),
    compatible,
    message,
    details,
  };
}

function versionCheck(id, title, result, minimum, required = true) {
  const version = parseVersion(`${result.stdout}\n${result.stderr}`);
  if (result.status !== 0 || !version) {
    return check(id, title, required, false, commandProblem(result), {minimum, version: null});
  }
  const compatible = versionAtLeast(version, minimum);
  return check(id, title, required, compatible,
    compatible ? `${version.text} meets minimum ${minimum}` : `${version.text} is below minimum ${minimum}`,
    {minimum, version: version.text});
}

function kubeVersion(value) {
  return parseVersion(value?.gitVersion ?? `${value?.major ?? ''}.${String(value?.minor ?? '').replace(/\D.*$/, '')}`);
}

function imageNames(node) {
  return new Set((node?.status?.images ?? []).flatMap(image => image?.names ?? []));
}

function kindContainerName(node) {
  const name = node?.metadata?.name;
  const match = /^kind:\/\/docker\/[^/]+\/([^/]+)$/.exec(node?.spec?.providerID ?? '');
  return match && match[1] === name ? name : null;
}

function normalizeImageReference(reference) {
  return String(reference ?? '')
    .replace(/^index\.docker\.io\//, '')
    .replace(/^docker\.io\//, '')
    .replace(/^library\//, '');
}

function imagePresent(names, reference) {
  const normalizedReference = normalizeImageReference(reference);
  if ([...names].some(name => normalizeImageReference(name) === normalizedReference)) return true;
  const digest = reference.includes('@sha256:') ? reference.slice(reference.indexOf('@') + 1) : null;
  return digest ? [...names].some(name => name.endsWith(`@${digest}`)) : false;
}

function normalizeClusterArch(value) {
  return value === 'x86_64' || value === 'x64' ? 'amd64' : value;
}

function defaultCheckPorts(ports) {
  return Promise.all(ports.map(port => new Promise(resolve => {
    const socket = net.createConnection({host: port.address, port: port.port});
    let settled = false;
    const finish = (available, error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({...port, available, error});
    };
    socket.unref();
    socket.setTimeout(500, () => finish(false, 'ETIMEDOUT'));
    socket.once('connect', () => finish(false, 'listener-present'));
    socket.once('error', error => finish(error.code === 'ECONNREFUSED', error.code ?? error.message));
  })));
}

async function defaultManagedPortNames(runCommand) {
  const definitions = [
    ['grafana', 'local-access.sh'],
    ['chaos-dashboard', 'chaos-dashboard.sh'],
  ];
  const managed = new Set();
  for (const [name, script] of definitions) {
    const result = await invoke(runCommand, 'bash', [join(attacknetDir, script), 'status']);
    if (result.status === 0 && /\brunning\b/.test(`${result.stdout}\n${result.stderr}`)) managed.add(name);
  }
  return managed;
}

function chaosVersion(releases) {
  const release = Array.isArray(releases)
    ? releases.find(item => item?.name === 'chaos-mesh' || String(item?.chart ?? '').startsWith('chaos-mesh-'))
    : null;
  if (!release) return {release: null, version: null};
  const chart = String(release.chart ?? '');
  const version = parseVersion(release.app_version ?? release.appVersion ?? chart.replace(/^chaos-mesh-/, ''));
  return {release, version};
}

function deriveCapabilities({crdNames, clusterArchitectures, daemonReady, metricsApi, imageResults}) {
  const allArchitectures = allowed => clusterArchitectures.length > 0 && clusterArchitectures.every(arch => allowed.includes(arch));
  const imageAvailable = name => imageResults.find(item => item.image === name)?.available === true;
  return {
    podChaos: daemonReady && crdNames.has('podchaos.chaos-mesh.org'),
    networkChaos: daemonReady && crdNames.has('networkchaos.chaos-mesh.org'),
    dnsChaos: daemonReady && crdNames.has('dnschaos.chaos-mesh.org'),
    nativeIoChaos: {
      admissionEligible: daemonReady && crdNames.has('iochaos.chaos-mesh.org')
        && allArchitectures(DOCTOR_CONTRACT.chaosMesh.nativeIoArchitectures),
      supportedArchitectures: [...DOCTOR_CONTRACT.chaosMesh.nativeIoArchitectures],
      portableAlternative: 'io-pressure',
    },
    nativeTimeChaos: {
      admissionEligible: daemonReady && crdNames.has('timechaos.chaos-mesh.org')
        && allArchitectures(DOCTOR_CONTRACT.chaosMesh.nativeTimeArchitectures),
      supportedArchitectures: [...DOCTOR_CONTRACT.chaosMesh.nativeTimeArchitectures],
      portableAlternative: 'clock-skew',
    },
    ioPressure: {available: imageAvailable('stacks-hacknet-io-pressure:dev'), semantic: 'bounded data-PVC pressure'},
    applicationClockSkew: {available: imageAvailable('stacks-core-attacknet:main'), semantic: 'process-visible realtime clock'},
    metricsApi,
  };
}

export async function collectDoctorReport({
  runCommand = defaultRunner,
  checkPorts = defaultCheckPorts,
  localArchitecture = process.arch,
  now = () => new Date().toISOString(),
  images = DOCTOR_CONTRACT.images,
  ports = DOCTOR_CONTRACT.localPorts,
  minimumStorageBytes = DOCTOR_CONTRACT.storage.minimumAvailableBytes,
  checkManagedPorts = defaultManagedPortNames,
} = {}) {
  const checks = [];
  const [nodeResult, pythonResult, dockerResult, kubeResult, helmResult, kindResult] = await Promise.all([
    invoke(runCommand, 'node', ['--version']),
    invoke(runCommand, 'python3', ['--version']),
    invoke(runCommand, 'docker', ['version', '--format', '{{json .}}']),
    invoke(runCommand, 'kubectl', ['version', '-o', 'json']),
    invoke(runCommand, 'helm', ['version', '--template', '{{.Version}}']),
    invoke(runCommand, 'kind', ['version']),
  ]);

  checks.push(versionCheck('tool.node', 'Node.js', nodeResult, DOCTOR_CONTRACT.tools.node.minimum));
  checks.push(versionCheck('tool.python', 'Python', pythonResult, DOCTOR_CONTRACT.tools.python.minimum));

  const docker = parseJson(dockerResult);
  const dockerClient = parseVersion(docker?.Client?.Version ?? docker?.client?.version);
  const dockerServer = parseVersion(docker?.Server?.Version ?? docker?.server?.version);
  checks.push(check('tool.docker', 'Docker client and daemon', true,
    dockerResult.status === 0 && Boolean(dockerClient && dockerServer),
    dockerResult.status === 0 && dockerClient && dockerServer
      ? `client ${dockerClient.text}, server ${dockerServer.text}` : commandProblem(dockerResult),
    {clientVersion: dockerClient?.text ?? null, serverVersion: dockerServer?.text ?? null}));

  const kube = parseJson(kubeResult);
  const kubeClient = kubeVersion(kube?.clientVersion);
  const kubeServer = kubeVersion(kube?.serverVersion);
  checks.push(check('tool.kubectl', 'kubectl client', true, kubeResult.status === 0 && Boolean(kubeClient),
    kubeClient ? `client ${kubeClient.text}` : commandProblem(kubeResult), {version: kubeClient?.text ?? null}));
  checks.push(check('kubernetes.server', 'Kubernetes API server', true,
    Boolean(kubeServer) && DOCTOR_CONTRACT.kubernetes.supportedMinors.includes(kubeServer.minor),
    kubeServer
      ? `server ${kubeServer.text}; supported minors: ${DOCTOR_CONTRACT.kubernetes.supportedMinors.join(', ')}`
      : 'server version unavailable',
    {version: kubeServer?.text ?? null, supportedMinors: [...DOCTOR_CONTRACT.kubernetes.supportedMinors]}));
  const skew = kubeClient && kubeServer ? Math.abs(kubeClient.minor - kubeServer.minor) : null;
  checks.push(check('kubernetes.client-server-skew', 'kubectl client/server skew', true,
    skew !== null && skew <= DOCTOR_CONTRACT.tools.kubectl.maximumMinorSkew,
    skew === null ? 'client/server skew unavailable'
      : `minor-version skew is ${skew}; maximum is ${DOCTOR_CONTRACT.tools.kubectl.maximumMinorSkew}`,
    {clientMinor: kubeClient?.minor ?? null, serverMinor: kubeServer?.minor ?? null, skew,
      maximumMinorSkew: DOCTOR_CONTRACT.tools.kubectl.maximumMinorSkew}));

  const helm = parseJson(helmResult);
  const helmVersion = parseVersion(helm?.version ?? helm?.Version ?? helmResult.stdout);
  const helmCompatible = helmResult.status === 0 && helmVersion
    && DOCTOR_CONTRACT.tools.helm.supportedMajors.includes(helmVersion.major);
  checks.push(check('tool.helm', 'Helm', true, Boolean(helmCompatible), helmVersion
    ? `${helmVersion.text}; supported majors: ${DOCTOR_CONTRACT.tools.helm.supportedMajors.join(', ')}`
    : commandProblem(helmResult), {version: helmVersion?.text ?? null, supportedMajors: [...DOCTOR_CONTRACT.tools.helm.supportedMajors]}));
  checks.push(versionCheck('tool.kind', 'kind CLI', kindResult, DOCTOR_CONTRACT.tools.kind.minimum,
    DOCTOR_CONTRACT.tools.kind.required));

  const [nodesResult, storageResult, crdResult, daemonResult, releasesResult, metricsResult] = await Promise.all([
    invoke(runCommand, 'kubectl', ['get', 'nodes', '-o', 'json']),
    invoke(runCommand, 'kubectl', ['get', 'storageclass', '-o', 'json']),
    invoke(runCommand, 'kubectl', ['get', 'crd', ...DOCTOR_CONTRACT.chaosMesh.requiredCrds, '-o', 'json']),
    invoke(runCommand, 'kubectl', ['-n', 'chaos-mesh', 'get', 'daemonset', 'chaos-daemon', '-o', 'json']),
    invoke(runCommand, 'helm', ['list', '-n', 'chaos-mesh', '-o', 'json']),
    invoke(runCommand, 'kubectl', ['get', '--raw', '/apis/metrics.k8s.io/v1beta1']),
  ]);
  const nodesDocument = parseJson(nodesResult);
  const nodes = Array.isArray(nodesDocument?.items) ? nodesDocument.items : [];
  const clusterArchitectures = [...new Set(nodes.map(node => normalizeClusterArch(
    node?.status?.nodeInfo?.architecture ?? node?.metadata?.labels?.['kubernetes.io/arch'],
  )).filter(Boolean))];
  const localArchCompatible = DOCTOR_CONTRACT.architectures.local.includes(localArchitecture);
  const clusterArchCompatible = clusterArchitectures.length > 0
    && clusterArchitectures.every(arch => DOCTOR_CONTRACT.architectures.cluster.includes(arch));
  checks.push(check('architecture', 'Local and cluster architecture', true,
    localArchCompatible && clusterArchCompatible,
    `local ${localArchitecture}; cluster ${clusterArchitectures.join(', ') || 'unavailable'}`,
    {local: localArchitecture, cluster: clusterArchitectures,
      supportedLocal: [...DOCTOR_CONTRACT.architectures.local], supportedCluster: [...DOCTOR_CONTRACT.architectures.cluster]}));

  const releases = parseJson(releasesResult);
  const installedChaos = chaosVersion(releases);
  const chaosCompatible = installedChaos.version
    && DOCTOR_CONTRACT.chaosMesh.supportedVersions.includes(installedChaos.version.text);
  checks.push(check('chaos-mesh.version', 'Chaos Mesh release', true, Boolean(chaosCompatible),
    installedChaos.version
      ? `${installedChaos.version.text}; supported: ${DOCTOR_CONTRACT.chaosMesh.supportedVersions.join(', ')}`
      : (releasesResult.status === 0 ? 'chaos-mesh Helm release not found' : commandProblem(releasesResult)),
    {version: installedChaos.version?.text ?? null, supportedVersions: [...DOCTOR_CONTRACT.chaosMesh.supportedVersions],
      chart: installedChaos.release?.chart ?? null}));

  const crds = parseJson(crdResult);
  const crdItems = Array.isArray(crds?.items) ? crds.items : [];
  const crdNames = new Set(crdItems.filter(item => (item?.status?.conditions ?? [])
    .some(condition => condition.type === 'Established' && condition.status === 'True'))
    .map(item => item?.metadata?.name));
  const missingCrds = DOCTOR_CONTRACT.chaosMesh.requiredCrds.filter(name => !crdNames.has(name));
  checks.push(check('chaos-mesh.crds', 'Chaos Mesh CRDs', true, crdResult.status === 0 && missingCrds.length === 0,
    missingCrds.length === 0 && crdResult.status === 0 ? 'all required CRDs are established'
      : `missing or unestablished: ${missingCrds.join(', ') || commandProblem(crdResult)}`,
    {required: [...DOCTOR_CONTRACT.chaosMesh.requiredCrds], established: [...crdNames], missing: missingCrds}));

  const daemon = parseJson(daemonResult);
  const desiredDaemons = Number(daemon?.status?.desiredNumberScheduled ?? 0);
  const readyDaemons = Number(daemon?.status?.numberReady ?? 0);
  const daemonImages = (daemon?.spec?.template?.spec?.containers ?? []).map(container => container.image).filter(Boolean);
  const daemonReady = daemonResult.status === 0 && desiredDaemons > 0 && readyDaemons === desiredDaemons
    && daemonImages.length > 0;
  checks.push(check('chaos-mesh.helpers', 'Chaos Mesh daemon and helpers', true, daemonReady,
    daemonReady ? `${readyDaemons}/${desiredDaemons} daemons ready; native IO/Time eligibility is architecture-gated`
      : (daemonResult.status === 0 ? `${readyDaemons}/${desiredDaemons} daemons ready` : commandProblem(daemonResult)),
    {desired: desiredDaemons, ready: readyDaemons, images: daemonImages,
      nativeIoArchitectures: [...DOCTOR_CONTRACT.chaosMesh.nativeIoArchitectures],
      nativeTimeArchitectures: [...DOCTOR_CONTRACT.chaosMesh.nativeTimeArchitectures]}));

  const metricsDocument = parseJson(metricsResult);
  const metricsApi = metricsResult.status === 0 && metricsDocument?.groupVersion === 'metrics.k8s.io/v1beta1';
  checks.push(check('kubernetes.metrics-api', 'Kubernetes Metrics API', false, metricsApi,
    metricsApi ? 'metrics.k8s.io/v1beta1 is available' : 'Metrics API unavailable; kubelet summary remains the bounded fallback',
    {groupVersion: metricsDocument?.groupVersion ?? null, fallback: 'kubelet-stats-summary'}));

  const storage = parseJson(storageResult);
  const storageClasses = Array.isArray(storage?.items) ? storage.items : [];
  const defaults = storageClasses.filter(item => item?.metadata?.annotations?.['storageclass.kubernetes.io/is-default-class'] === 'true'
    || item?.metadata?.annotations?.['storageclass.beta.kubernetes.io/is-default-class'] === 'true');
  const capacityResults = [];
  for (const node of nodes) {
    const name = node?.metadata?.name;
    if (!name) continue;
    const result = await invoke(runCommand, 'kubectl', ['get', '--raw', `/api/v1/nodes/${name}/proxy/stats/summary`]);
    const summary = parseJson(result);
    const availableBytes = Number(summary?.node?.fs?.availableBytes);
    capacityResults.push({node: name, availableBytes: Number.isFinite(availableBytes) ? availableBytes : null,
      compatible: result.status === 0 && Number.isFinite(availableBytes) && availableBytes >= minimumStorageBytes,
      error: result.status === 0 && Number.isFinite(availableBytes) ? null : commandProblem(result)});
  }
  const storageCompatible = storageResult.status === 0 && defaults.length === 1 && capacityResults.length === nodes.length
    && nodes.length > 0 && capacityResults.every(item => item.compatible);
  checks.push(check('storage', 'Storage class and node capacity', true, storageCompatible,
    storageCompatible ? `default ${defaults[0].metadata.name}; every node has at least ${minimumStorageBytes} bytes free`
      : 'requires exactly one default StorageClass and sufficient kubelet filesystem capacity on every node',
    {minimumAvailableBytes: minimumStorageBytes,
      defaultStorageClasses: defaults.map(item => ({name: item.metadata.name, provisioner: item.provisioner,
        volumeBindingMode: item.volumeBindingMode ?? null})), nodes: capacityResults}));

  const imageResults = [];
  const nodeImageInventories = new Map();
  for (const node of nodes) {
    const names = imageNames(node);
    const container = kindContainerName(node);
    let source = 'kubelet-node-status';
    if (container) {
      const result = await invoke(runCommand, 'docker', [
        'exec', container, 'ctr', '-n', 'k8s.io', 'images', 'ls', '-q',
      ]);
      if (result.status === 0) {
        for (const name of result.stdout.split('\n').map(value => value.trim()).filter(Boolean)) names.add(name);
        source = 'kind-containerd-and-kubelet';
      }
    }
    nodeImageInventories.set(node?.metadata?.name, {names, source});
  }
  for (const image of images) {
    const result = await invoke(runCommand, 'docker', ['image', 'inspect', image, '--format', '{{json .}}']);
    const inspected = parseJson(result);
    const loadedOnNodes = nodes.filter(node => imagePresent(
      nodeImageInventories.get(node.metadata.name)?.names ?? imageNames(node), image,
    )).map(node => node.metadata.name);
    const inDocker = result.status === 0 && Boolean(inspected);
    const immutableRemote = image.includes('@sha256:');
    const loadedOnEveryNode = nodes.length > 0 && loadedOnNodes.length === nodes.length;
    const available = nodes.length > 0 ? immutableRemote || loadedOnEveryNode : immutableRemote || inDocker;
    imageResults.push({image, available, resolution: immutableRemote ? 'remote-immutable'
      : loadedOnEveryNode ? 'loaded-on-every-node' : inDocker ? 'docker-daemon-only' : 'unavailable',
    docker: inDocker, dockerId: inspected?.Id ?? null, loadedOnNodes,
    nodeInventorySources: Object.fromEntries(nodes.map(node => [
      node.metadata.name, nodeImageInventories.get(node.metadata.name)?.source ?? 'unavailable',
    ])),
    requiredNodeCount: nodes.length, immutableRemote});
  }
  const imagesCompatible = imageResults.length > 0 && imageResults.every(item => item.available);
  checks.push(check('images', 'Declared Attacknet images', true, imagesCompatible,
    imagesCompatible ? 'every local image is loaded on every cluster node or is remotely digest-pinned'
      : `unavailable: ${imageResults.filter(item => !item.available).map(item => item.image).join(', ')}`,
    {images: imageResults}));

  let portResults;
  let managedPortNames = new Set();
  try {
    portResults = await checkPorts(ports.map(port => ({...port})));
    managedPortNames = await checkManagedPorts(runCommand);
  } catch (error) {
    portResults = ports.map(port => ({...port, available: false, error: String(error?.message ?? error)}));
  }
  portResults = portResults.map(item => ({...item, managedByAttacknet: managedPortNames.has(item.name)}));
  const conflicts = portResults.filter(item => !item.available && !item.managedByAttacknet);
  const portsCompatible = portResults.length === ports.length && conflicts.length === 0;
  checks.push(check('local-ports', 'Local loopback ports', true, portsCompatible,
    portsCompatible ? 'all declared loopback ports are available or owned by an Attacknet supervisor'
      : `conflicts: ${conflicts.map(item => `${item.address}:${item.port}`).join(', ')}`,
    {ports: portResults}));

  const capabilities = deriveCapabilities({crdNames, clusterArchitectures, daemonReady, metricsApi, imageResults});
  checks.push(check('chaos-mesh.native-io-helper', 'Native Chaos Mesh IO helper', false,
    capabilities.nativeIoChaos.admissionEligible,
    capabilities.nativeIoChaos.admissionEligible ? 'eligible on every cluster architecture'
      : `not eligible on ${clusterArchitectures.join(', ') || 'unknown architecture'}; use io-pressure without calling it IOChaos`,
    capabilities.nativeIoChaos));
  checks.push(check('chaos-mesh.native-time-helper', 'Native Chaos Mesh time helper', false,
    capabilities.nativeTimeChaos.admissionEligible,
    capabilities.nativeTimeChaos.admissionEligible ? 'eligible on every cluster architecture'
      : `not eligible on ${clusterArchitectures.join(', ') || 'unknown architecture'}; use clock-skew without calling it TimeChaos`,
    capabilities.nativeTimeChaos));
  const requiredFailures = checks.filter(item => item.required && !item.compatible).map(item => item.id);
  return {
    schemaVersion: DOCTOR_CONTRACT.schemaVersion,
    observedAt: now(),
    compatible: requiredFailures.length === 0,
    summary: {
      pass: checks.filter(item => item.status === 'pass').length,
      warn: checks.filter(item => item.status === 'warn').length,
      fail: checks.filter(item => item.status === 'fail').length,
      requiredFailures,
    },
    declared: DOCTOR_CONTRACT,
    observed: {
      localArchitecture,
      clusterArchitectures,
      nodeNames: nodes.map(node => node?.metadata?.name).filter(Boolean),
    },
    capabilities,
    checks,
  };
}

export function formatDoctorReport(report) {
  const lines = [`Attacknet doctor: ${report.compatible ? 'compatible' : 'incompatible'}`];
  for (const item of report.checks) {
    const marker = item.status === 'pass' ? 'PASS' : item.status === 'warn' ? 'WARN' : 'FAIL';
    lines.push(`[${marker}] ${item.title}: ${item.message}`);
  }
  lines.push(`Summary: ${report.summary.pass} passed, ${report.summary.warn} warnings, ${report.summary.fail} failed`);
  return `${lines.join('\n')}\n`;
}

export async function runDoctor(argv, dependencies = {}) {
  if (argv.some(argument => argument !== '--json') || argv.filter(argument => argument === '--json').length > 1) {
    return {status: 2, stdout: '', stderr: 'usage: attacknet doctor [--json]\n'};
  }
  const report = await collectDoctorReport(dependencies);
  return {
    status: report.compatible ? 0 : 1,
    stdout: argv.includes('--json') ? `${JSON.stringify(report, null, 2)}\n` : formatDoctorReport(report),
    stderr: '',
    report,
  };
}

async function main() {
  const result = await runDoctor(process.argv.slice(2));
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.status;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
