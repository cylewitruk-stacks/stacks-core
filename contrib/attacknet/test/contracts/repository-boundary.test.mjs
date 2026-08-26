import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync, readdirSync, statSync} from 'node:fs';
import {dirname, join, relative, resolve, sep} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const attacknetRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const repositoryRoot = resolve(attacknetRoot, '..', '..');
const legacyRoot = join(attacknetRoot, 'legacy', 'v1alpha1');
const manifest = JSON.parse(readFileSync(join(legacyRoot, 'manifest.v1.json'), 'utf8'));
const trackedPaths = new Set(execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
}).split('\0').filter(Boolean));
const allowedRootEntries = new Set([
  '.gitignore', 'README.md', 'config', 'docs', 'evidence', 'evidence-packets',
  'examples', 'generated', 'images', 'instrumentation', 'legacy',
  'observability', 'release', 'test', 'testdata',
]);

function filesBelow(root, accept) {
  const files = [];
  for (const entry of readdirSync(root, {withFileTypes: true})) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...filesBelow(path, accept));
    else if (entry.isFile() && accept(path)) files.push(path);
  }
  return files;
}

function isInside(root, path) {
  const local = relative(root, path);
  return local !== '..' && !local.startsWith(`..${sep}`) && !local.includes(`${sep}..${sep}`);
}

function assertRepositoryFile(path, label) {
  assert.equal(path.startsWith('/') || path.includes('\\'), false, `${label} must be a portable repository-relative path`);
  const resolved = resolve(repositoryRoot, path);
  assert.equal(isInside(repositoryRoot, resolved), true, `${label} escapes the repository`);
  assert.equal(statSync(resolved).isFile(), true, `${label} does not resolve to a file`);
  assert.equal(trackedPaths.has(path), true, `${label} is not tracked by Git`);
}

function assertTrackedDocumentationTarget(path, label) {
  const local = relative(repositoryRoot, path).split(sep).join('/').replace(/\/$/, '');
  const tracked = trackedPaths.has(local)
    || [...trackedPaths].some(candidate => candidate.startsWith(`${local}/`));
  assert.equal(tracked, true, `${label} is not present in a clean checkout`);
}

test('legacy runtime entries are qualification-only and bound to implemented Go successors', () => {
  assert.equal(manifest.schema, 'stacks-attacknet-legacy-runtime/v1');
  assert.equal(manifest.policy, 'internal-qualification-only');
  assert.ok(manifest.entries.length > 0);

  const paths = manifest.entries.map(entry => entry.path);
  assert.equal(new Set(paths).size, paths.length, 'legacy runtime paths must be unique');
  const retainedFiles = filesBelow(join(legacyRoot, 'runtime'), () => true)
    .map(path => relative(legacyRoot, path).split(sep).join('/'))
    .sort();
  assert.deepEqual([...paths].sort(), retainedFiles,
    'every retained legacy file must have an explicit owner and removal gate');
  for (const entry of manifest.entries) {
    assert.match(entry.path, /\.(?:mjs|sh)$/);
    assert.equal(entry.disposition, 'retained-qualification');
    assert.match(entry.owner, /^(?:fault-controller|instrumentation|release-qualification|topology-controller)$/);
    assert.ok(entry.successors.length > 0, `${entry.path} has no Go successor`);
    assert.ok(entry.removalGates.length > 0, `${entry.path} has no removal gate`);
    assertRepositoryFile(`contrib/attacknet/legacy/v1alpha1/${entry.path}`, entry.path);
    for (const successor of entry.successors) assertRepositoryFile(successor, `${entry.path} successor`);
  }
});

test('public operator guides expose only the typed Go surface', () => {
  const publicGuides = [
    join(attacknetRoot, 'README.md'),
    ...filesBelow(join(attacknetRoot, 'docs'), path => path.endsWith('.md')),
    join(repositoryRoot, 'contrib', 'helm', 'hacknet', 'README.md'),
  ];
  for (const path of publicGuides) {
    const source = readFileSync(path, 'utf8');
    assert.doesNotMatch(source, /contrib\/attacknet\/attacknet(?:\s|`|$)/,
      `${relative(repositoryRoot, path)} advertises the retired Node facade`);
    for (const entry of manifest.entries) {
      const name = entry.path.split('/').at(-1);
      assert.doesNotMatch(source, new RegExp(name.replaceAll('.', '\\.')),
        `${relative(repositoryRoot, path)} advertises qualification-only helper ${name}`);
    }
  }
});

test('the Attacknet root is an explicit product-directory allowlist', () => {
  const entries = readdirSync(attacknetRoot);
  assert.deepEqual(entries.filter(entry => !allowedRootEntries.has(entry)), [],
    'loose root files must be placed under their owning product directory');
  assertRepositoryFile('contrib/helm/hacknet/operator/cmd/attacknet/main.go', 'canonical Go CLI');
});

test('v1beta1 YAML examples do not invoke compatibility runtime helpers', () => {
  const names = manifest.entries.map(entry => entry.path.split('/').at(-1));
  const exampleRoots = [join(attacknetRoot, 'examples'), join(repositoryRoot, 'contrib', 'helm', 'hacknet', 'examples')];
  for (const path of exampleRoots.flatMap(root => filesBelow(root, candidate => /\.ya?ml$/.test(candidate)))) {
    const source = readFileSync(path, 'utf8');
    for (const name of names) assert.doesNotMatch(source, new RegExp(name.replaceAll('.', '\\.')),
      `${relative(repositoryRoot, path)} invokes compatibility helper ${name}`);
  }
});

test('local Markdown links in current Attacknet documentation resolve', () => {
  const documentation = [
    join(attacknetRoot, 'README.md'),
    ...['config', 'docs', 'examples', 'images', 'legacy', 'test']
      .flatMap(directory => filesBelow(join(attacknetRoot, directory), path => path.endsWith('.md'))),
    join(attacknetRoot, 'observability', 'README.md'),
    join(attacknetRoot, 'release', 'README.md'),
  ];
  for (const path of documentation) {
    const source = readFileSync(path, 'utf8');
    for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = match[1].split('#', 1)[0];
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      const resolved = resolve(dirname(path), decodeURIComponent(target));
      assert.equal(isInside(repositoryRoot, resolved), true, `${relative(repositoryRoot, path)} link escapes the repository`);
      assert.doesNotThrow(() => statSync(resolved),
        `${relative(repositoryRoot, path)} has dangling link ${target}`);
      assertTrackedDocumentationTarget(resolved,
        `${relative(repositoryRoot, path)} link ${target}`);
    }
  }
});
