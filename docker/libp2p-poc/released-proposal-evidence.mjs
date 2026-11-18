import fs from 'node:fs';
import {pathToFileURL} from 'node:url';

function stripAnsi(line) {
  return line.replace(/\x1b\[[0-9;]*m/g, '');
}

export function findReleasedProposalEvidence(text, signer = 'signer') {
  return findAllReleasedProposalEvidence(text, signer)
    .find(evidence => [
      'local-precommit',
      'canonicalized-before-local-vote',
      'canonicalized-after-release',
      'canonicalized-while-deferred',
    ].includes(evidence.outcome)) ?? null;
}

export function findAllReleasedProposalEvidence(text, signer = 'signer') {
  const lines = text.split('\n').map(stripAnsi);
  const evidence = [];
  for (let released = 0; released < lines.length; released += 1) {
    if (!lines[released].includes('was_deferred=true')) continue;
    const signerSignatureHash = lines[released]
      .match(/signer_signature_hash=([0-9a-f]{64})/)?.[1];
    if (!signerSignatureHash) continue;

    const hasHash = line => line.includes(signerSignatureHash);
    const deferred = lines.findIndex((line, index) => index < released
      && line.includes('deferred source-bound miner envelope') && hasHash(line));
    if (deferred < 0) {
      evidence.push({
        signer,
        signerSignatureHash,
        outcome: 'released-without-observed-deferral',
        releasedLine: released,
      });
      continue;
    }

    const submitted = lines.findIndex((line, index) => index > released
      && line.includes('submitting block proposal for validation') && hasHash(line));
    const precommit = submitted < 0 ? -1 : lines.findIndex((line, index) => index > submitted
      && line.includes('Broadcasting block pre-commit') && hasHash(line));
    const isCanonicalEvent = line => (line.includes('Got block pushed message')
      || line.includes('Received a new block event')) && hasHash(line);
    const canonicalizedWhileDeferred = lines.findIndex((line, index) =>
      index > deferred && index < released && isCanonicalEvent(line));
    const canonicalizedAfterRelease = lines.findIndex((line, index) =>
      index > released && isCanonicalEvent(line));

    if (submitted > released && precommit > submitted) {
      evidence.push({
        signer,
        signerSignatureHash,
        outcome: 'local-precommit',
        deferredLine: deferred,
        releasedLine: released,
        submittedLine: submitted,
        terminalLine: precommit,
      });
      continue;
    }
    if (canonicalizedAfterRelease > released) {
      evidence.push({
        signer,
        signerSignatureHash,
        outcome: submitted > released && canonicalizedAfterRelease > submitted
          ? 'canonicalized-before-local-vote'
          : 'canonicalized-after-release',
        deferredLine: deferred,
        releasedLine: released,
        submittedLine: submitted,
        terminalLine: canonicalizedAfterRelease,
      });
      continue;
    }
    if (canonicalizedWhileDeferred > deferred) {
      evidence.push({
        signer,
        signerSignatureHash,
        outcome: 'canonicalized-while-deferred',
        deferredLine: deferred,
        releasedLine: released,
        terminalLine: canonicalizedWhileDeferred,
      });
      continue;
    }
    evidence.push({
      signer,
      signerSignatureHash,
      outcome: 'released-without-observed-terminal',
      deferredLine: deferred,
      releasedLine: released,
      submittedLine: submitted,
    });
  }
  return evidence;
}

export function summarizeReleasedProposalEvidence(text, signer = 'signer') {
  const proposals = findAllReleasedProposalEvidence(text, signer);
  const outcomes = {};
  for (const proposal of proposals) {
    outcomes[proposal.outcome] = (outcomes[proposal.outcome] ?? 0) + 1;
  }
  return {signer, releases: proposals.length, outcomes, proposals};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const text = fs.readFileSync(0, 'utf8');
  const signer = process.argv[2] ?? 'signer';
  if (process.argv.includes('--all')) {
    console.log(JSON.stringify(summarizeReleasedProposalEvidence(text, signer)));
    process.exit(0);
  }
  const evidence = findReleasedProposalEvidence(text, signer);
  if (!evidence) process.exit(1);
  console.log(JSON.stringify(evidence));
}
