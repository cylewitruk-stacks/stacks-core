import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {loadEnrollments} from './enrollment.js';

const key = '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c';
const peer = '16Uiu2HAmU1MbqEPd87m36aZWn6qKUtPumc2SthnzhF4h2RXz4wTS';

test('loads a server-owned signer binding and rejects duplicate key ownership', () => {
  const directory = mkdtempSync(join(tmpdir(), 'observer-enrollment-'));
  const path = join(directory, 'actors.json');
  try {
    writeFileSync(path, JSON.stringify({
      version: 1,
      network: 'regtest',
      actors: [
        {id: 'poc-companion', label: 'Companion', role: 'companion', transportPeerId: peer},
        {id: 'poc-signer-one', label: 'Signer', role: 'signer', signerPublicKey: key, transportPeerId: '16Uiu2HAm7K2fEAn5W93hqHt3qhjMKTdDCDDPfyykqEcrgNNBAoqn', companionActorId: 'poc-companion'},
      ],
      signerEntities: [{publicKey: key, entityName: 'Example entity'}],
    }));
    const actors = loadEnrollments(path, undefined);
    assert.equal(actors[1]?.signerPublicKey, key);
    assert.equal(actors[1]?.entityName, 'Example entity');
    assert.equal(actors[0]?.transportPeerId, peer);

    writeFileSync(path, JSON.stringify({
      version: 1,
      network: 'regtest',
      actors: [
        {id: 'poc-signer-one', label: 'One', role: 'signer', signerPublicKey: key},
        {id: 'poc-signer-two', label: 'Two', role: 'signer', signerPublicKey: key},
      ],
    }));
    assert.throws(() => loadEnrollments(path, undefined), /multiple actors/);

    writeFileSync(path, JSON.stringify({
      version: 1,
      network: 'regtest',
      actors: [
        {id: 'poc-node-one', label: 'One', role: 'companion', transportPeerId: peer},
        {id: 'poc-node-two', label: 'Two', role: 'follower', transportPeerId: peer},
      ],
    }));
    assert.throws(() => loadEnrollments(path, undefined), /transport PeerId is bound to multiple actors/);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
