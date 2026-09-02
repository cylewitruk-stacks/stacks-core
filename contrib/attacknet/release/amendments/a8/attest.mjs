#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {
  bindA8SignedCandidate, validateA8CandidateAttestation, validateA8Verification,
} from './verify.mjs';

function digestFile(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

/** Create the only post-sign A8 artifact without rebuilding qualification evidence. */
export function createA8CandidateAttestation({candidateRevision, verificationPath, summaryPath, outputPath}) {
  const rawVerification = JSON.parse(readFileSync(resolve(verificationPath), 'utf8'));
  const verification = validateA8Verification(rawVerification, rawVerification.qualifiedTree);
  const summaryDigest = digestFile(resolve(summaryPath));
  const attestation = bindA8SignedCandidate(candidateRevision, verification, summaryDigest);
  validateA8CandidateAttestation(attestation, verification, summaryDigest);
  writeFileSync(resolve(outputPath), `${JSON.stringify(attestation, null, 2)}\n`, {mode: 0o600});
  return attestation;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--verification=', '--summary=', '--output='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const options = {
    candidateRevision: value('--candidate='), verificationPath: value('--verification='),
    summaryPath: value('--summary='), outputPath: value('--output='),
  };
  for (const [name, option] of Object.entries(options)) if (!option) throw new Error(`${name} is required`);
  process.stdout.write(`${JSON.stringify(createA8CandidateAttestation(options), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
