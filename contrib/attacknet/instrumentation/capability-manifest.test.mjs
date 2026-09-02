import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {compileCapabilityManifest, loadInventory} from './capability-manifest.mjs';

const sha = letter => `sha256:${letter.repeat(64)}`;
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function seal(value, field) {
  value[field] = `sha256:${createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex')}`;
  return value;
}
function sourceStateDigest(revision, patch) {
  const hash = createHash('sha256');
  hash.update('stacks-attacknet-source-state-v1\0');
  hash.update(revision);
  hash.update('\0patch\0');
  hash.update(patch);
  return `sha256:${hash.digest('hex')}`;
}
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-instrumentation-'));
  const revision = '1'.repeat(40);
  const patchContents = 'diff --git a/a b/a\n';
  const patchPath = join(root, 'workstream-m.patch'); writeFileSync(patchPath, patchContents);
  const inventory = loadInventory();
  const inventoryBytes = readFileSync(new URL('./inventory-v1.json', import.meta.url));
  const contextDigest = sha('9');
  const build = seal({
    schema: 'stacks-attacknet-image-build-record/v1', pipelineId: 'release', profileId: 'patched-main',
    source: {kind: 'localModified', revision, dirty: true, untrackedFiles: [], sourceStateDigest: sourceStateDigest(revision, patchContents)}, imageDigest: sha('a'), immutableRef: `stacks@${sha('a')}`,
    localRef: 'stacks:content-abc', stagedContextDigest: contextDigest, buildInvocation: {digest: sha('f')},
    imageIdentity: {imageIndexDigest: sha('a'), platformManifestDigest: sha('b'), runtimeConfigDigest: sha('c'), expectedRuntimeImageID: sha('c')},
    instrumentationSourceAudit: {
      method: 'exact-source-string-audit/v1', inventoryVersion: inventory.inventoryVersion,
      inventoryDigest: `sha256:${createHash('sha256').update(inventoryBytes).digest('hex')}`,
      sourceContextDigest: contextDigest, familiesPresent: inventory.families.map(item => item.id),
    },
  }, 'recordDigest');
  const buildPath = join(root, 'build.json'); writeFileSync(buildPath, JSON.stringify(build));
  const admission = seal({
    schema: 'stacks-attacknet-image-admission-evidence/v1', result: 'Passed',
    build: {recordDigest: build.recordDigest, runtimeConfigDigest: sha('c')},
    admission: {actor: 'signer-1', network: 'net', networkUID: 'net-uid', pod: 'pod', podUID: 'pod-uid', runtimeDigest: sha('c')},
  }, 'evidenceDigest');
  const admissionPath = join(root, 'admission.json'); writeFileSync(admissionPath, JSON.stringify(admission));
  const smoke = seal({
    schema: 'stacks-attacknet-config-startup-smoke/v1', result: 'Passed', profileId: 'patched-main',
    requestedImage: 'stacks:content-abc', actor: 'signer-1', role: 'signer', binary: 'stacks-signer', command: ['docker'],
    config: {sourceDigest: sha('d'), parserInputDigest: sha('d')},
  }, 'evidenceDigest');
  const smokePath = join(root, 'smoke.json'); writeFileSync(smokePath, JSON.stringify(smoke));
  const requiredFamilies = inventory.families.filter(item => item.roles.includes('signer')).map(item => item.family);
  const metricsPath = join(root, 'metrics.prom'); writeFileSync(metricsPath, 'fixture metrics\n');
  const metricsDigest = `sha256:${createHash('sha256').update(readFileSync(metricsPath)).digest('hex')}`;
  const runtime = seal({
    schema: 'stacks-attacknet-runtime-metric-presence/v1', result: 'Passed', profileId: 'patched-main',
    requestedImage: 'stacks:content-abc', actor: 'signer-1', role: 'signer', podUID: 'pod-uid', runtimeImageID: sha('c'),
    inventoryDigest: `sha256:${createHash('sha256').update(inventoryBytes).digest('hex')}`,
    requiredFamilies, presentFamilies: requiredFamilies, missingFamilies: [], metricsDigest,
    metricsArtifact: {path: metricsPath, digest: metricsDigest},
  }, 'evidenceDigest');
  const runtimePath = join(root, 'runtime.json'); writeFileSync(runtimePath, JSON.stringify(runtime));
  return {root, revision, buildPath, admissionPath, smokePath, runtimePath, patchPath};
}

test('the portable inventory freezes exactly 22 bounded families', () => {
  const inventory = loadInventory();
  assert.equal(inventory.families.length, 22);
  assert.equal(new Set(inventory.families.map(family => family.family)).size, 22);
  assert.ok(inventory.families.every(family => family.maxSeriesPerProcess <= 512));
  const milestones = inventory.families.find(family => family.id === 'M21');
  assert.deepEqual(milestones.labels.milestone, ['proposal_to_first_response', 'proposal_to_threshold']);
  assert.doesNotMatch(JSON.stringify(milestones), /first_response_to_threshold/);
});

test('the carried Workstream M patch metadata binds exact contents and excludes pre-existing M14', () => {
  const contents = readFileSync(new URL('./workstream-m.patch', import.meta.url));
  const metadata = JSON.parse(readFileSync(new URL('./workstream-m.patch.json', import.meta.url), 'utf8'));
  assert.equal(`sha256:${createHash('sha256').update(contents).digest('hex')}`, metadata.digest);
  assert.equal(metadata.upstreamBaseRevision, '6b002604da0533e69f4ebdceb2747954f496a3ea');
  assert.equal(sourceStateDigest(metadata.upstreamBaseRevision, contents), metadata.expectedSourceStateDigest);
  assert.deepEqual(metadata.families, Array.from({length: 22}, (_, index) => `M${String(index + 1).padStart(2, '0')}`).filter(id => id !== 'M14'));
  assert.match(contents.toString(), /pub fn initialize_signer_coordinator_metrics\(\)/);
  assert.match(contents.toString(), /stacks::monitoring::initialize_signer_coordinator_metrics\(\);/);
  assert.match(contents.toString(), /fn initialize_proposal_outcome_metrics\(\)/);
  assert.match(contents.toString(), /super::initialize_proposal_outcome_metrics\(\);/);
});

test('added-file patch headers identify the exact added blob contents', () => {
  const patch = readFileSync(new URL('./workstream-m.patch', import.meta.url), 'utf8');
  const blocks = patch.split(/^diff --git /m).slice(1);
  let addedFiles = 0;
  for (const block of blocks) {
    if (!/^new file mode /m.test(block)) continue;
    const index = block.match(/^index 0+\.\.([0-9a-f]+)$/m)?.[1];
    assert.ok(index, 'new-file patch block must declare its resulting Git blob');
    const hunk = block.slice(block.indexOf('@@'));
    const lines = hunk.split('\n').slice(1)
      .filter(line => line.startsWith('+') && !line.startsWith('+++'))
      .map(line => line.slice(1));
    const contents = Buffer.from(`${lines.join('\n')}\n`);
    const hash = createHash('sha1')
      .update(`blob ${contents.length}\0`)
      .update(contents)
      .digest('hex');
    assert.equal(hash.slice(0, index.length), index);
    addedFiles += 1;
  }
  assert.equal(addedFiles, 4);
});

test('capability output binds patch, build, admitted Pod, runtime image, smoke, and each signal', () => {
  const data = fixture();
  const manifest = compileCapabilityManifest({
    schemaVersion: 1, manifestId: 'phase-1', inventoryVersion: 'workstream-m/1', profiles: [{
      id: 'patched-main', requestedImage: 'stacks:content-abc', actors: [{name: 'signer-1', role: 'signer'}],
      defaultProvenance: 'attacknet-patch', signals: {}, effectiveEventDispatchMode: 'queued',
      patch: {path: data.patchPath, upstreamBaseRevision: data.revision}, buildRecordPath: data.buildPath,
      admissionEvidencePaths: [data.admissionPath], configSmokeEvidencePaths: [data.smokePath], runtimeMetricEvidencePaths: [data.runtimePath],
    }],
  }, {baseDirectory: data.root, acceptance: true});
  assert.equal(manifest.acceptanceReady, true);
  assert.equal(manifest.profiles[0].signals.length, 22);
  assert.equal(manifest.profiles[0].signals.find(signal => signal.id === 'M14').provenance, 'merged');
  assert.ok(manifest.profiles[0].signals.filter(signal => signal.id !== 'M14').every(signal => signal.provenance === 'attacknet-patch'));
  assert.equal(manifest.profiles[0].admissions[0].podUID, 'pod-uid');
  assert.equal(manifest.profiles[0].build.expectedRuntimeImageID, sha('c'));
  assert.match(manifest.interpretation.sourceAudit, /producer assertion/);
  assert.match(manifest.interpretation.sourceAudit, /runtime metric-presence evidence is mandatory and authoritative/);
});

test('unmodified image degrades truthfully and acceptance fails without its config smoke', () => {
  const input = {schemaVersion: 1, manifestId: 'release', inventoryVersion: 'workstream-m/1', profiles: [{
    id: 'release', requestedImage: 'stacks:v1', actors: [{name: 'signer-1', role: 'signer'}],
    defaultProvenance: 'unavailable', signals: {}, effectiveEventDispatchMode: 'unknown',
  }]};
  const manifest = compileCapabilityManifest(input);
  assert.equal(manifest.acceptanceReady, false);
  assert.equal(manifest.profiles[0].capability.status, 'unavailable');
  assert.match(manifest.unresolvedReasons.join('\n'), /configuration-startup smoke/);
  assert.throws(() => compileCapabilityManifest(input, {acceptance: true}), /not acceptance-ready/);
});

test('patch provenance fails closed without contents or exact build-source equality', () => {
  const data = fixture();
  const base = {schemaVersion: 1, manifestId: 'phase-1', inventoryVersion: 'workstream-m/1', profiles: [{
    id: 'patched-main', requestedImage: 'stacks:content-abc', actors: [{name: 'signer-1', role: 'signer'}],
    defaultProvenance: 'attacknet-patch', signals: {}, buildRecordPath: data.buildPath,
  }]};
  assert.throws(() => compileCapabilityManifest(base), /patch.path is required/);
  base.profiles[0].patch = {path: data.patchPath, upstreamBaseRevision: data.revision};
  writeFileSync(data.patchPath, 'diff --git a/different b/different\n');
  assert.throws(() => compileCapabilityManifest(base), /patch bytes do not match the build source-state digest/);
});

test('merged provenance fails closed without source audit and runtime presence evidence', () => {
  const data = fixture();
  const input = {schemaVersion: 1, manifestId: 'merged', inventoryVersion: 'workstream-m/1', profiles: [{
    id: 'patched-main', requestedImage: 'stacks:content-abc', actors: [{name: 'signer-1', role: 'signer'}],
    defaultProvenance: 'merged', signals: {}, buildRecordPath: data.buildPath,
    admissionEvidencePaths: [data.admissionPath], configSmokeEvidencePaths: [data.smokePath],
  }]};
  const withoutRuntime = compileCapabilityManifest(input, {baseDirectory: data.root});
  assert.equal(withoutRuntime.acceptanceReady, false);
  assert.match(withoutRuntime.unresolvedReasons.join('\n'), /runtime metric-presence/);

  const build = JSON.parse(readFileSync(data.buildPath, 'utf8'));
  delete build.instrumentationSourceAudit;
  delete build.recordDigest;
  seal(build, 'recordDigest');
  writeFileSync(data.buildPath, JSON.stringify(build));
  assert.throws(() => compileCapabilityManifest(input, {baseDirectory: data.root}), /build-time instrumentation source audit/);
});
