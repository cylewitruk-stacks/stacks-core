#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const KEY_PATTERN = /^(02|03)[0-9a-f]{64}$/;

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex')}`;
}

function positiveWeight(value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} must be a positive integer`);
  return value;
}

function publicKey(value, field) {
  if (typeof value !== 'string' || !KEY_PATTERN.test(value)) {
    throw new Error(`${field} must be a compressed secp256k1 public key`);
  }
  return value;
}

export function declaredSignerSet(manifest) {
  const actors = manifest?.actors ?? manifest?.workloads;
  if (!Array.isArray(actors)) throw new Error('manifest lacks actors/workloads');
  const signers = actors.filter(actor => actor.role === 'signer' || actor.type === 'signer');
  if (signers.length === 0) throw new Error('manifest declares no signers');
  const indexes = new Set();
  const keys = new Set();
  const entries = signers.map(actor => {
    const name = actor.service ?? actor.name;
    if (!Number.isSafeInteger(actor.signerIndex) || actor.signerIndex <= 0) {
      throw new Error(`declared signer ${name ?? '?'} lacks signerIndex`);
    }
    if (indexes.has(actor.signerIndex)) throw new Error(`duplicate declared signer index ${actor.signerIndex}`);
    indexes.add(actor.signerIndex);
    const signingKey = publicKey(actor.signerPublicKey, `declared signer ${name ?? '?'} public key`);
    if (keys.has(signingKey)) throw new Error(`duplicate declared signer public key ${signingKey}`);
    keys.add(signingKey);
    return {
      index: actor.signerIndex,
      actor: name,
      signingKey,
      weight: positiveWeight(actor.signerWeight, `declared signer ${name ?? '?'} weight`),
    };
  }).sort((left, right) => left.index - right.index);
  return entries;
}

export function observedSignerSet(response) {
  const signers = response?.stacker_set?.signers;
  if (!Array.isArray(signers) || signers.length === 0) throw new Error('reward-set response has no signers');
  const keys = new Set();
  return signers.map((signer, index) => {
    const signingKey = publicKey(signer.signing_key, `observed signer ${index} public key`);
    if (keys.has(signingKey)) throw new Error(`duplicate observed signer public key ${signingKey}`);
    keys.add(signingKey);
    return {
      signingKey,
      weight: positiveWeight(signer.weight, `observed signer ${signingKey} weight`),
    };
  }).sort((left, right) => left.signingKey.localeCompare(right.signingKey));
}

function signerSetReport(manifest, response, {rewardCycle = null} = {}) {
  const declared = declaredSignerSet(manifest);
  const observed = observedSignerSet(response);
  const declaredByKey = new Map(declared.map(signer => [signer.signingKey, signer]));
  const observedByKey = new Map(observed.map(signer => [signer.signingKey, signer]));
  const missing = declared.filter(signer => !observedByKey.has(signer.signingKey));
  const unexpected = observed.filter(signer => !declaredByKey.has(signer.signingKey));
  const mismatched = declared.flatMap(signer => {
    const live = observedByKey.get(signer.signingKey);
    return live && live.weight !== signer.weight
      ? [{actor: signer.actor, signingKey: signer.signingKey, declared: signer.weight, observed: live.weight}]
      : [];
  });
  const declaredTotal = declared.reduce((total, signer) => total + signer.weight, 0);
  const observedTotal = observed.reduce((total, signer) => total + signer.weight, 0);
  const report = {
    schemaVersion: 'stacks-attacknet-signer-set-parity/v1',
    ok: missing.length === 0 && unexpected.length === 0 && mismatched.length === 0,
    rewardCycle,
    declaredCount: declared.length,
    observedCount: observed.length,
    declaredTotalWeight: declaredTotal,
    observedTotalWeight: observedTotal,
    canonicalThresholdWeight: Math.ceil(observedTotal * 0.7),
    missing: missing.map(({index, actor, signingKey, weight}) => ({index, actor, signingKey, weight})),
    unexpected,
    mismatched,
    signerSetDigest: digest(observed),
  };
  return {declared, observed, observedByKey, report};
}

export function verifySignerSetParity(manifest, response, {rewardCycle = null} = {}) {
  const {report} = signerSetReport(manifest, response, {rewardCycle});
  if (!report.ok) {
    const error = new Error(`declared signer set does not match reward cycle ${rewardCycle ?? 'unknown'}`);
    error.report = report;
    throw error;
  }
  return report;
}

// The topology owns signer identities, while the active PoX reward set owns
// voting weights. Fixed stacked amounts can legitimately acquire different
// weights as the PoX threshold changes between reward cycles. Runtime fault
// admission must therefore require exact key-set identity but charge safety
// budgets against the canonical weights observed for the current cycle.
export function resolveCanonicalSignerSet(manifest, response, {rewardCycle = null} = {}) {
  const {observedByKey, report} = signerSetReport(manifest, response, {rewardCycle});
  if (report.missing.length > 0 || report.unexpected.length > 0) {
    const error = new Error(`declared signer identities do not match reward cycle ${rewardCycle ?? 'unknown'}`);
    error.report = {...report, ok: false};
    throw error;
  }
  const resolved = structuredClone(manifest);
  const actors = resolved.actors ?? resolved.workloads;
  for (const actor of actors) {
    if (actor.signerIndex === undefined) continue;
    const live = observedByKey.get(actor.signerPublicKey);
    if (!live) {
      const error = new Error(`signer-bound actor ${actor.service ?? actor.name ?? '?'} is absent from reward cycle ${rewardCycle ?? 'unknown'}`);
      error.report = {...report, ok: false};
      throw error;
    }
    actor.signerWeight = live.weight;
  }
  return {
    manifest: resolved,
    report: {
      ...report,
      schemaVersion: 'stacks-attacknet-canonical-signer-set/v1',
      ok: true,
      identityMatch: true,
      weightsMatch: report.mismatched.length === 0,
    },
  };
}

function runCli(argv) {
  const [manifestPath, responsePath, outputPath] = argv;
  if (!manifestPath || !responsePath) {
    throw new Error('usage: signer-set-parity.mjs MANIFEST REWARD_SET_JSON [OUTPUT]');
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const response = JSON.parse(readFileSync(responsePath, 'utf8'));
  const cycle = Number.parseInt(process.env.ATTACKNET_REWARD_CYCLE ?? '', 10);
  let report;
  try {
    report = verifySignerSetParity(manifest, response, {
      rewardCycle: Number.isSafeInteger(cycle) && cycle >= 0 ? cycle : null,
    });
  } catch (error) {
    if (!error.report) throw error;
    report = error.report;
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    if (outputPath) writeFileSync(outputPath, serialized);
    else process.stdout.write(serialized);
    process.exitCode = 1;
    return;
  }
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (outputPath) writeFileSync(outputPath, serialized);
  else process.stdout.write(serialized);
}

if (process.argv[1]
    && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  try { runCli(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 2; }
}
