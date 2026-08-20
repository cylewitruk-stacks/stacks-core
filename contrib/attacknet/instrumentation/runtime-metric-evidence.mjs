#!/usr/bin/env node

import {createHash} from 'node:crypto';

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestValue(value) { return digestBytes(JSON.stringify(canonical(value))); }

export function metricFamilies(metrics) {
  const names = new Set();
  for (const line of metrics.split(/\r?\n/)) {
    const metadata = line.match(/^# (?:HELP|TYPE) ([a-zA-Z_:][a-zA-Z0-9_:]*)\b/);
    if (metadata) names.add(metadata[1]);
    const sample = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{|\s)/);
    if (sample) names.add(sample[1]);
  }
  return names;
}

function observed(names, family, type) {
  if (names.has(family)) return true;
  if (type === 'counter' && names.has(`${family}_total`)) return true;
  if (type === 'histogram' && ['_bucket', '_sum', '_count'].some(suffix => names.has(`${family}${suffix}`))) return true;
  return false;
}

export function buildRuntimeMetricEvidence({profileId, requestedImage, actor, role, podUID, runtimeImageID, inventory, inventoryDigest, requiredFamilies, metrics, metricsArtifact, collectedAt = new Date().toISOString()}) {
  const names = metricFamilies(metrics);
  const required = [...requiredFamilies].sort();
  const types = new Map(inventory.families.map(family => [family.family, family.type]));
  const presentFamilies = required.filter(family => observed(names, family, types.get(family))).sort();
  const missingFamilies = required.filter(family => !presentFamilies.includes(family)).sort();
  const evidence = {
    schema: 'stacks-attacknet-runtime-metric-presence/v1',
    result: missingFamilies.length === 0 ? 'Passed' : 'Failed',
    profileId, requestedImage, actor, role, podUID, runtimeImageID,
    inventoryDigest: inventoryDigest ?? digestBytes(JSON.stringify(inventory)),
    requiredFamilies: required, presentFamilies, missingFamilies,
    metricsDigest: digestBytes(metrics), metricsArtifact: metricsArtifact ?? null, collectedAt,
    trust: 'orchestrator-read-from-admitted-actor-endpoint',
  };
  evidence.evidenceDigest = digestValue(evidence);
  return evidence;
}
