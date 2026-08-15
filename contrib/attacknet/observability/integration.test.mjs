import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = new URL('.', import.meta.url).pathname;

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-observability-integration-'));
  const kubectl = join(directory, 'kubectl.mjs');
  writeFileSync(kubectl, `#!/usr/bin/env node
import {readFileSync, writeFileSync} from 'node:fs';
const args=process.argv.slice(2);
if (args.includes('get') && args.includes('pods')) {
  if (args.at(-1) === 'json' && process.env.FAKE_PODS) process.stdout.write(process.env.FAKE_PODS);
  else process.stdout.write('trusted-event-pod');
} else if (args.includes('get') && args.includes('configmap')) {
  const name=args[args.indexOf('configmap')+1];
  if (name.endsWith('-burnchain-policy') && process.env.FAKE_POLICY) process.stdout.write(process.env.FAKE_POLICY);
  else if (name.endsWith('-run-context') && process.env.FAKE_RUN_ID) process.stdout.write(process.env.FAKE_RUN_ID);
  else process.exitCode=1;
} else if (args.includes('exec') && args.includes('-i')) {
  const body=readFileSync(0, 'utf8');
  if (process.env.FAKE_APPEND === '1') {
    const prior=(()=>{try{return readFileSync(process.env.FAKE_EVENT_CAPTURE, 'utf8')}catch{return ''}})();
    writeFileSync(process.env.FAKE_EVENT_CAPTURE, prior+body.trim()+'\\n');
  } else writeFileSync(process.env.FAKE_EVENT_CAPTURE, body);
  writeFileSync(process.env.FAKE_ARGUMENT_CAPTURE, JSON.stringify(args));
  process.stdout.write('{"inserted":true}\\n');
} else if (args.includes('exec') && args.join(' ').includes('/run/hacknet-policy/policy.env')) {
  process.stdout.write(process.env.FAKE_POLICY_GENERATION ?? '2');
} else if (args.includes('exec') && args.join(' ').includes('/tmp/hacknet-burnchain-clock.env')) {
  process.stdout.write(process.env.FAKE_POLICY_GENERATION ?? '2');
} else if (args.includes('exec') && args.at(-1) === 'kill -USR2 1') {
  // Successful clock wakeup.
} else if (args.includes('exec')) {
  const after=Number(args.at(-2)), limit=Number(args.at(-1));
  const events=JSON.parse(process.env.FAKE_EVENTS).filter(event=>event.sequence>after).slice(0, limit);
  process.stdout.write(JSON.stringify({schemaVersion:1, events}));
} else if (args.includes('patch') || args.includes('annotate')) {
  // Successful policy update/projection request.
} else {
  process.stderr.write('unexpected fake kubectl invocation: '+JSON.stringify(args));
  process.exitCode=3;
}
`);
  chmodSync(kubectl, 0o755);
  return {directory, kubectl};
}

test('trusted event writer fixes network and run identity outside caller payload', () => {
  const {directory, kubectl} = fixture();
  const capture = join(directory, 'event.json');
  const argumentsCapture = join(directory, 'args.json');
  const result = spawnSync(join(root, 'record-event.sh'), [
    '--kind=note', '--phase=baseline', '--network=attacker-controlled',
    '--run-id=attacker-controlled', '--details={"message":"hello"}',
  ], {encoding: 'utf8', env: {
    ...process.env,
    ATTACKNET_KUBECTL: kubectl,
    ATTACKNET_RUN_ID: 'trusted-run',
    KUBE_NETWORK: 'trusted-network',
    KUBE_NAMESPACE: 'trusted-namespace',
    FAKE_EVENT_CAPTURE: capture,
    FAKE_ARGUMENT_CAPTURE: argumentsCapture,
  }});
  assert.equal(result.status, 0, result.stderr);
  const event = JSON.parse(readFileSync(capture, 'utf8'));
  assert.equal(event.network, 'trusted-network');
  assert.equal(event.runId, 'trusted-run');
  assert.equal(event.details.message, 'hello');
  const invocation = readFileSync(argumentsCapture, 'utf8');
  assert.doesNotMatch(invocation, /trusted-run|hello/);
});

test('trusted event writer resolves the persisted run context without exposing it in arguments', () => {
  const {directory, kubectl} = fixture();
  const capture = join(directory, 'event.json');
  const argumentsCapture = join(directory, 'args.json');
  const result = spawnSync(join(root, 'record-event.sh'), ['--kind=note', '--details={}'], {
    encoding: 'utf8', env: {
      ...process.env, ATTACKNET_KUBECTL: kubectl, ATTACKNET_RUN_ID: '',
      FAKE_RUN_ID: 'persisted-run', FAKE_EVENT_CAPTURE: capture,
      FAKE_ARGUMENT_CAPTURE: argumentsCapture,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(capture, 'utf8')).runId, 'persisted-run');
  assert.doesNotMatch(readFileSync(argumentsCapture, 'utf8'), /persisted-run/);
});

test('trusted event writer refuses an unattributed run', () => {
  const {directory, kubectl} = fixture();
  const result = spawnSync(join(root, 'record-event.sh'), ['--kind=note'], {
    encoding: 'utf8', env: {...process.env, ATTACKNET_KUBECTL: kubectl, ATTACKNET_RUN_ID: ''},
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /run-context has no run-id/);
});

test('Kubernetes export paginates and filters the retained journal by run', () => {
  const {directory, kubectl} = fixture();
  const events = [
    {schemaVersion: 1, sequence: 1, eventId: 'one', runId: 'run-1', network: 'attacknet', kind: 'note', phase: 'baseline', occurredAt: '2026-08-15T00:00:00Z', recordedAt: '2026-08-15T00:00:01Z', details: {}},
    {schemaVersion: 1, sequence: 2, eventId: 'two', runId: 'run-2', network: 'attacknet', kind: 'note', phase: 'baseline', occurredAt: '2026-08-15T00:00:02Z', recordedAt: '2026-08-15T00:00:03Z', details: {}},
    {schemaVersion: 1, sequence: 3, eventId: 'three', runId: 'run-1', network: 'attacknet', kind: 'note', phase: 'verification', occurredAt: '2026-08-15T00:00:04Z', recordedAt: '2026-08-15T00:00:05Z', details: {}},
  ];
  const output = join(directory, 'evidence');
  const result = spawnSync(join(root, 'export-kubernetes-report.sh'), [output, 'run-1'], {
    encoding: 'utf8', env: {
      ...process.env,
      ATTACKNET_KUBECTL: kubectl,
      ATTACKNET_EVENT_PAGE_LIMIT: '2',
      FAKE_EVENTS: JSON.stringify(events),
      KUBE_NETWORK: 'attacknet',
      KUBE_NAMESPACE: 'hacknet-system',
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const exported = readFileSync(join(output, 'timeline.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(exported.map(event => event.eventId), ['one', 'three']);
  assert.equal(JSON.parse(readFileSync(join(output, 'export.json'), 'utf8')).pageCount, 2);
  assert.equal(JSON.parse(readFileSync(join(output, 'timeline.html.summary.json'), 'utf8')).eventCount, 2);
  assert.match(readFileSync(join(output, 'timeline.html'), 'utf8'), /Stacks Attacknet incident timeline/);
});

test('explicitly disabled observability needs no cluster and leaves a truthful export marker', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-observability-disabled-'));
  const output = join(directory, 'timeline');
  const exportResult = spawnSync(join(root, 'export-kubernetes-report.sh'), [output, 'run-disabled'], {
    encoding: 'utf8', env: {...process.env, ATTACKNET_OBSERVABILITY_ENABLED: '0'},
  });
  assert.equal(exportResult.status, 0, exportResult.stderr);
  const metadata = JSON.parse(readFileSync(join(output, 'export.json'), 'utf8'));
  assert.equal(metadata.source, 'disabled-by-configuration');
  assert.equal(metadata.eventCount, 0);
  assert.match(readFileSync(join(output, 'timeline.html'), 'utf8'), /Stacks Attacknet incident timeline/);

  const writerResult = spawnSync(join(root, 'record-event.sh'), ['--kind=note'], {
    encoding: 'utf8', env: {...process.env, ATTACKNET_OBSERVABILITY_ENABLED: '0'},
  });
  assert.equal(writerResult.status, 0, writerResult.stderr);
});

test('applied burnchain policy is journaled only after clock acknowledgement', () => {
  const {directory, kubectl} = fixture();
  const capture = join(directory, 'policy-event.json');
  const argumentsCapture = join(directory, 'args.json');
  const policy = 'GENERATION=1\nMODE=run\nINTERVAL_SECONDS=20\nJITTER_SECONDS=0\nBURST_BLOCKS=0\nADDRESS_MODE=round-robin\nFIXED_ADDRESS_INDEX=0\n';
  const result = spawnSync(join(root, '..', 'burnchain-policy.sh'), ['pause'], {
    encoding: 'utf8', env: {
      ...process.env,
      ATTACKNET_KUBECTL: kubectl,
      ATTACKNET_RUN_ID: 'policy-run',
      FAKE_POLICY: policy,
      FAKE_POLICY_GENERATION: '2',
      FAKE_EVENT_CAPTURE: capture,
      FAKE_ARGUMENT_CAPTURE: argumentsCapture,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const event = JSON.parse(readFileSync(capture, 'utf8'));
  assert.equal(event.kind, 'policy.changed');
  assert.deepEqual(event.details, {
    mode: 'pause', generation: 2, intervalSeconds: 20, jitterSeconds: 0,
    burstBlocks: 0, addressMode: 'round-robin', fixedAddressIndex: 0, applied: true,
  });
});

test('exact burnchain bursts retain an inter-block bootstrap cadence and end paused', () => {
  const {directory, kubectl} = fixture();
  const capture = join(directory, 'burst-event.json');
  const argumentsCapture = join(directory, 'args.json');
  const policy = 'GENERATION=4\nMODE=run\nINTERVAL_SECONDS=60\nJITTER_SECONDS=0\nBURST_BLOCKS=0\nADDRESS_MODE=round-robin\nFIXED_ADDRESS_INDEX=0\n';
  const result = spawnSync(join(root, '..', 'burnchain-policy.sh'), ['burst', '3', '2'], {
    encoding: 'utf8', env: {
      ...process.env,
      ATTACKNET_KUBECTL: kubectl,
      ATTACKNET_RUN_ID: 'burst-run',
      FAKE_POLICY: policy,
      FAKE_POLICY_GENERATION: '5',
      FAKE_EVENT_CAPTURE: capture,
      FAKE_ARGUMENT_CAPTURE: argumentsCapture,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const event = JSON.parse(readFileSync(capture, 'utf8'));
  assert.deepEqual(event.details, {
    mode: 'pause', generation: 5, intervalSeconds: 2, jitterSeconds: 0,
    burstBlocks: 3, addressMode: 'round-robin', fixedAddressIndex: 0, applied: true,
  });
});

test('verification recorder emits each bounded assertion through the trusted writer', () => {
  const {directory, kubectl} = fixture();
  const resultPath = join(directory, 'verification.json');
  const capture = join(directory, 'verification-events.jsonl');
  const argumentsCapture = join(directory, 'args.json');
  writeFileSync(resultPath, JSON.stringify({
    ok: true, ceiling: 2, minimumStacksHeight: 1, minimumObservedStacksHeight: 9,
    burnDrift: 1, stacksDrift: 0, forkedHeights: [],
    peerConnectivity: {ok: true, minimumAuthenticatedConnections: 2},
  }));
  const result = spawnSync(join(root, 'record-verification.sh'), [resultPath, 'baseline', 'baseline'], {
    encoding: 'utf8', env: {
      ...process.env, ATTACKNET_KUBECTL: kubectl, ATTACKNET_RUN_ID: 'verify-run',
      FAKE_APPEND: '1', FAKE_EVENT_CAPTURE: capture, FAKE_ARGUMENT_CAPTURE: argumentsCapture,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const events = readFileSync(capture, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(events.length, 6);
  assert.ok(events.every(event => event.kind === 'invariant.observed' && event.outcome === 'pass'));
  assert.ok(events.some(event => event.details.name === 'baseline.canonical-tip-agreement'));
});

test('actor-state recorder uses admitted Pod state rather than actor self-report', () => {
  const {directory, kubectl} = fixture();
  const capture = join(directory, 'actor-events.jsonl');
  const argumentsCapture = join(directory, 'args.json');
  const pods = {items: [{
    metadata: {name: 'attacknet-miner-1-0', uid: 'pod-uid', labels: {
      'testing.stacks.org/actor': 'miner-1', 'testing.stacks.org/role': 'miner',
    }},
    spec: {nodeName: 'worker'},
    status: {phase: 'Running', conditions: [{type: 'Ready', status: 'True'}], containerStatuses: [
      {name: 'actor', ready: true, restartCount: 1, imageID: 'sha256:resolved'},
    ]},
  }]};
  const result = spawnSync(join(root, 'record-actor-states.sh'), ['verification'], {
    encoding: 'utf8', env: {
      ...process.env, ATTACKNET_KUBECTL: kubectl, ATTACKNET_RUN_ID: 'actor-run',
      FAKE_PODS: JSON.stringify(pods), FAKE_APPEND: '1',
      FAKE_EVENT_CAPTURE: capture, FAKE_ARGUMENT_CAPTURE: argumentsCapture,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const event = JSON.parse(readFileSync(capture, 'utf8'));
  assert.equal(event.kind, 'actor.state');
  assert.equal(event.actor, 'miner-1');
  assert.equal(event.details.ready, true);
  assert.equal(event.details.restarts, 1);
  assert.equal(event.details.imageId, undefined);
  assert.equal(event.details.containers[0].imageId, 'sha256:resolved');
});
