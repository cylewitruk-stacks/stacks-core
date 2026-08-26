import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const dockerfile = readFileSync(new URL('./Dockerfile', import.meta.url), 'utf8');
const dockerignore = readFileSync(new URL('./Dockerfile.dockerignore', import.meta.url), 'utf8');
const runtime = dockerfile.split(/^FROM \$\{RUNTIME_IMAGE\}$/m)[1];

test('attacknet runtime strips only DWARF and exposes matching external symbols', () => {
  assert.match(dockerfile, /cargo build\s+\\\n\s+--profile release-lite/);
  assert.match(dockerfile, /objcopy --only-keep-debug/);
  assert.match(dockerfile, /strip --strip-debug/);
  assert.match(dockerfile, /objcopy\s+\\\n\s+--add-gnu-debuglink=/);
  assert.doesNotMatch(dockerfile, /strip --strip-(?:all|unneeded)/);
  assert.match(dockerfile, /^FROM scratch AS debug-symbols$/m);
  assert.match(dockerfile, /sha256sum runtime\/bin\/\* debug\/usr\/lib\/debug\/bin\/\*/);
  assert.match(dockerfile, /schema=stacks-attacknet-debug-symbols\/v1/);
  assert.match(dockerfile, /git_commit=\$\{GIT_COMMIT\}/);
});

test('default runtime excludes external DWARF and preserves operational dependencies', () => {
  assert.ok(runtime, 'runtime stage must exist');
  assert.match(dockerfile, /^ARG RUNTIME_IMAGE=debian:bookworm-slim$/m);
  assert.match(runtime, /ca-certificates curl/);
  assert.match(runtime, /COPY --from=build \/out\/runtime\/bin\/stacks-node \/bin\/stacks-node/);
  assert.match(runtime, /COPY --from=build \/out\/runtime\/SHA256SUMS/);
  assert.match(runtime, /COPY --from=build \/out\/runtime\/BUILD-INFO/);
  assert.doesNotMatch(runtime, /\/out\/debug\/|\.debug(?:\s|$)/m);
});

test('reproducible cargo-chef and incremental-build controls remain intact', () => {
  assert.match(dockerfile, /^ARG CARGO_CHEF_VERSION=0\.1\.77$/m);
  assert.match(dockerfile, /cargo chef prepare --recipe-path recipe\.json/);
  assert.match(dockerfile, /cargo chef cook/);
  assert.match(dockerfile, /^ENV CARGO_INCREMENTAL=0$/m);
  assert.match(dockerfile, /--mount=type=cache,id=stacks-attacknet-target,target=\/src\/target/);
});

test('Stacks image context excludes local evidence and build artifacts', () => {
  const patterns = new Set(dockerignore.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#')));
  for (const required of ['.docs', '.git', 'target']) {
    assert.ok(patterns.has(required), `Dockerfile.dockerignore must exclude ${required}`);
  }
});
