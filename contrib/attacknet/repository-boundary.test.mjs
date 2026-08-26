import assert from 'node:assert/strict';
import {readFileSync, readdirSync, statSync} from 'node:fs';
import {dirname, join, relative, resolve, sep} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const attacknetRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(attacknetRoot, '..', '..');
const manifest = JSON.parse(readFileSync(join(attacknetRoot, 'legacy', 'manifest.v1.json'), 'utf8'));
const registry = JSON.parse(readFileSync(join(attacknetRoot, 'command-registry.v1.json'), 'utf8'));

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
}

test('legacy runtime entries are qualification-only and bound to implemented Go successors', () => {
  assert.equal(manifest.schema, 'stacks-attacknet-legacy-runtime/v1');
  assert.equal(manifest.policy, 'internal-qualification-only');
  assert.ok(manifest.entries.length > 0);

  const paths = manifest.entries.map(entry => entry.path);
  assert.equal(new Set(paths).size, paths.length, 'legacy runtime paths must be unique');
  for (const entry of manifest.entries) {
    assert.match(entry.path, /\.(?:mjs|sh)$/);
    assert.equal(entry.disposition, 'retained-qualification');
    assert.match(entry.owner, /^(?:burnchain-clock|burnchain-policy-controller|fault-controller|go-cli|run-controller)$/);
    assert.ok(entry.successors.length > 0, `${entry.path} has no Go successor`);
    assert.ok(entry.removalGates.length > 0, `${entry.path} has no removal gate`);
    assertRepositoryFile(`contrib/attacknet/${entry.path}`, entry.path);
    for (const successor of entry.successors) assertRepositoryFile(successor, `${entry.path} successor`);
  }
});

test('public operator guides expose only the typed Go surface', () => {
  const publicGuides = [
    join(attacknetRoot, 'README.md'),
    join(attacknetRoot, 'OPERATIONS.md'),
    join(attacknetRoot, 'GO-CLI.md'),
    join(repositoryRoot, 'contrib', 'helm', 'hacknet', 'README.md'),
  ];
  for (const path of publicGuides) {
    const source = readFileSync(path, 'utf8');
    assert.doesNotMatch(source, /contrib\/attacknet\/attacknet(?:\s|`|$)/,
      `${relative(repositoryRoot, path)} advertises the retired Node facade`);
    for (const entry of manifest.entries) assert.doesNotMatch(source, new RegExp(entry.path.replaceAll('.', '\\.')),
      `${relative(repositoryRoot, path)} advertises qualification-only helper ${entry.path}`);
  }
});

test('the public legacy registry contains no dangling helper or command implementation paths', () => {
  const helperSet = new Set(registry.internalHelpers);
  assert.equal(helperSet.size, registry.internalHelpers.length);
  for (const helper of helperSet) assertRepositoryFile(`contrib/attacknet/${helper}`, `registry helper ${helper}`);
  for (const command of registry.commands) {
    const path = command.implementation?.path;
    if (!path) continue;
    assert.ok(helperSet.has(path), `${command.name} dispatches an unclassified helper ${path}`);
    assertRepositoryFile(`contrib/attacknet/${path}`, `${command.name} implementation`);
  }
});

test('v1beta1 YAML examples do not invoke compatibility runtime helpers', () => {
  const names = manifest.entries.map(entry => entry.path);
  const exampleRoots = [join(attacknetRoot, 'examples'), join(repositoryRoot, 'contrib', 'helm', 'hacknet', 'examples')];
  for (const path of exampleRoots.flatMap(root => filesBelow(root, candidate => /\.ya?ml$/.test(candidate)))) {
    const source = readFileSync(path, 'utf8');
    for (const name of names) assert.doesNotMatch(source, new RegExp(name.replaceAll('.', '\\.')),
      `${relative(repositoryRoot, path)} invokes compatibility helper ${name}`);
  }
});

test('local Markdown links under the compatibility boundary resolve', () => {
  const root = join(attacknetRoot, 'legacy');
  for (const path of filesBelow(root, candidate => candidate.endsWith('.md'))) {
    const source = readFileSync(path, 'utf8');
    for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = match[1].split('#', 1)[0];
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      const resolved = resolve(dirname(path), decodeURIComponent(target));
      assert.equal(isInside(repositoryRoot, resolved), true, `${relative(repositoryRoot, path)} link escapes the repository`);
      assert.equal(statSync(resolved).isFile(), true, `${relative(repositoryRoot, path)} has dangling link ${target}`);
    }
  }
});
