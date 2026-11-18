import assert from 'node:assert/strict';
import test from 'node:test';

import {
  findAllReleasedProposalEvidence,
  findReleasedProposalEvidence,
  summarizeReleasedProposalEvidence,
} from './released-proposal-evidence.mjs';

const HASH = '36cd004ee83075a5f73f60f448a588a0b49cecd0ef04dbc9d4d22e8d233d65be';
const OTHER_HASH = '420a8530aac8539b95ba46427be040a72adad4176f5d7666f91153f3c9909880';

function line(message, hash = HASH) {
  return `${message} signer_signature_hash=${hash}`;
}

test('correlates an exact released envelope through local precommit', () => {
  const evidence = findReleasedProposalEvidence([
    line('deferred source-bound miner envelope'),
    line('\x1b[32maccepted envelope was_deferred=true\x1b[0m'),
    line('submitting block proposal for validation'),
    line('Broadcasting block pre-commit'),
  ].join('\n'), 'signer-1');
  assert.equal(evidence?.outcome, 'local-precommit');
  assert.equal(evidence?.signerSignatureHash, HASH);
});

test('accepts canonicalization immediately after release without local validation', () => {
  const evidence = findReleasedProposalEvidence([
    line('deferred source-bound miner envelope'),
    line('accepted envelope was_deferred=true'),
    line('Received a new block event.'),
  ].join('\n'));
  assert.equal(evidence?.outcome, 'canonicalized-after-release');
});

test('accepts a proposal that canonicalized while still deferred', () => {
  const evidence = findReleasedProposalEvidence([
    line('deferred source-bound miner envelope'),
    line('Got block pushed message'),
    line('accepted envelope was_deferred=true'),
  ].join('\n'));
  assert.equal(evidence?.outcome, 'canonicalized-while-deferred');
});

test('does not correlate an unrelated proposal terminal', () => {
  const evidence = findReleasedProposalEvidence([
    line('deferred source-bound miner envelope'),
    line('accepted envelope was_deferred=true'),
    line('Broadcasting block pre-commit', OTHER_HASH),
    line('Received a new block event.', OTHER_HASH),
  ].join('\n'));
  assert.equal(evidence, null);
});

test('classifies every release for non-blocking soak evidence', () => {
  const evidence = findAllReleasedProposalEvidence([
    line('deferred source-bound miner envelope'),
    line('accepted envelope was_deferred=true'),
    line('submitting block proposal for validation'),
    line('Broadcasting block pre-commit'),
    line('deferred source-bound miner envelope', OTHER_HASH),
    line('accepted envelope was_deferred=true', OTHER_HASH),
  ].join('\n'), 'signer-4');
  assert.deepEqual(
    evidence.map(item => item.outcome),
    ['local-precommit', 'released-without-observed-terminal'],
  );
  assert.ok(evidence.every(item => item.signer === 'signer-4'));
});

test('summarizes release outcomes without treating no evidence as an error', () => {
  assert.deepEqual(summarizeReleasedProposalEvidence('', 'signer-2'), {
    signer: 'signer-2',
    releases: 0,
    outcomes: {},
    proposals: [],
  });
});
