import {spawnSync} from 'node:child_process';
import {mkdtempSync, realpathSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

const materializedSourceEnvironment = 'ATTACKNET_A9_MATERIALIZED_SOURCE';
const inheritedGitEnvironment = ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE', 'GIT_WORK_TREE'];

function execute(executable, arguments_, {cwd, env = process.env, stdio = 'pipe'} = {}) {
  const result = spawnSync(executable, arguments_, {
    cwd, env, stdio, encoding: stdio === 'pipe' ? 'utf8' : undefined, maxBuffer: 128 << 20,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${executable} ${arguments_.join(' ')} failed: ${result.error?.message ?? result.stderr ?? result.stdout ?? ''}`);
  }
  return String(result.stdout ?? '').trim();
}

function isolatedEnvironment() {
  const environment = {...process.env};
  for (const name of inheritedGitEnvironment) delete environment[name];
  return environment;
}

/** Materialize one immutable candidate tree in an isolated shared clone. */
export function materializeQualifiedTree(repositoryRoot, qualifiedTree) {
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree ?? '')) throw new Error('qualified tree must be a full Git tree SHA');
  const root = mkdtempSync(join(tmpdir(), 'attacknet-a9-source-'));
  const sourceRoot = join(root, 'source');
  try {
    const environment = isolatedEnvironment();
    const sourceHead = execute('git', ['rev-parse', 'HEAD'], {cwd: repositoryRoot, env: environment});
    execute('git', ['clone', '--shared', '--no-checkout', '--quiet', '--', repositoryRoot, sourceRoot], {cwd: root, env: environment});
    execute('git', ['update-ref', '--no-deref', 'HEAD', sourceHead], {cwd: sourceRoot, env: environment});
    execute('git', ['read-tree', '--reset', '-u', qualifiedTree], {cwd: sourceRoot, env: environment});
    execute('git', ['diff-files', '--quiet', '--'], {cwd: sourceRoot, env: environment});
    const unexpected = execute('git', ['ls-files', '--others', '--exclude-standard'], {cwd: sourceRoot, env: environment});
    if (unexpected) throw new Error(`materialized qualified tree contains unexpected files: ${unexpected}`);
    return {sourceRoot, environment: {...environment, [materializedSourceEnvironment]: sourceRoot}, cleanup: () => rmSync(root, {recursive: true, force: true})};
  } catch (error) {
    rmSync(root, {recursive: true, force: true});
    throw error;
  }
}

/** Re-execute a qualification entrypoint from its immutable source tree. */
export function runMaterializedEntrypoint({repositoryRoot, qualifiedTree, script, arguments_}) {
  const materialized = materializeQualifiedTree(repositoryRoot, qualifiedTree);
  try {
    execute(process.execPath, [join(materialized.sourceRoot, script), ...arguments_], {cwd: materialized.sourceRoot, env: materialized.environment, stdio: 'inherit'});
  } finally {
    materialized.cleanup();
  }
}

/** Report whether this process is already running from the materialized tree. */
export function isMaterializedSource(repositoryRoot) {
  try {
    return Boolean(process.env[materializedSourceEnvironment])
      && realpathSync(process.env[materializedSourceEnvironment]) === realpathSync(repositoryRoot);
  } catch {
    return false;
  }
}

/** Compare an entrypoint by canonical filesystem identity. */
export function isMainModule(importMetaURL, argument = process.argv[1]) {
  try {
    return Boolean(argument) && realpathSync(argument) === realpathSync(fileURLToPath(importMetaURL));
  } catch {
    return false;
  }
}
