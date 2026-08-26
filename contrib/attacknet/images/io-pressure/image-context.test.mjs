import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const dockerfile = readFileSync(new URL('./Dockerfile', import.meta.url), 'utf8');
const source = readFileSync(new URL('./main.go', import.meta.url), 'utf8');

test('runtime image is a non-root static entrypoint without a shell', () => {
  assert.match(dockerfile, /FROM scratch/);
  assert.match(dockerfile, /USER 65532:65532/);
  assert.match(dockerfile, /ENTRYPOINT \["\/attacknet-io-pressure"\]/);
  assert.doesNotMatch(dockerfile.split('FROM scratch')[1], /\bRUN\b|\/bin\/sh|bash/);
});

test('pressure executable bounds every input and unlinks scratch before worker startup', () => {
  for (const fragment of [
    'bounded(durationSeconds, 1, 300', 'bounded(workers, 1, 4',
    'bounded(bytesMiB, 16, 512', 'bounded(writeSizeKiB, 4, 1024',
  ]) assert.match(source, new RegExp(fragment.replace(/[()]/g, '\\$&')));
  const unlink = source.indexOf('os.Remove(name)');
  const removeDirectory = source.indexOf('os.Remove(scratchPath)');
  const startWorker = source.indexOf('go func(file *os.File)');
  assert.ok(unlink >= 0 && removeDirectory > unlink && startWorker > removeDirectory);
  assert.doesNotMatch(source, /os\.Exec|exec\.Command|\/bin\/sh/);
});
