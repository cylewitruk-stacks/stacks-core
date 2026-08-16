# Reproducible mixed-version attacknet images

`image-build-pipeline.mjs` turns exact current, released, and locally modified
source states into locally loadable images and immutable build evidence. It is
deliberately separate from Kubernetes admission: building or loading an image
does not prove which bytes an actor Pod eventually ran.

## Safety and reproducibility boundary

Running the command without flags is read-only with respect to Docker, kind,
and Kubernetes:

```sh
node contrib/attacknet/image-build-pipeline.mjs \
  contrib/attacknet/examples/mixed-version-images.plan.json
```

The example contains invalid placeholder registries for the two base images.
Replace both with real digest references before execution. Mutable base tags
are rejected because the content-derived output tag would otherwise be able to
name different bytes on different days.

An actual build is explicit and writes its evidence outside the source
repository:

```sh
node contrib/attacknet/image-build-pipeline.mjs /absolute/pipeline.json \
  --execute \
  --output-dir=/tmp/attacknet-image-evidence
```

Loading the resulting content tag into kind is a second explicit action:

```sh
node contrib/attacknet/image-build-pipeline.mjs /absolute/pipeline.json \
  --execute \
  --output-dir=/tmp/attacknet-image-evidence \
  --load-kind=desktop-linux
```

Neither mode writes to the Kubernetes API. The optional kind operation only
adds the local image to the named kind nodes.

## What is pinned

For every profile the planner records:

- the resolved 40-character Git revision;
- a digest of the current/local-modified Git patch and untracked files;
- an explicit expected revision for released Git refs;
- the staged build-context digest;
- the cargo-chef Dockerfile digest;
- digest-pinned cargo-chef and runtime base images;
- the platform, Cargo profile, features, binaries, and `CARGO_INCREMENTAL=0`;
- BuildKit's metadata and maximum-mode provenance;
- the resulting OCI image-index digest and immutable
  `repository@sha256:...` reference;
- the selected platform-manifest digest and the runtime config digest that a
  Kubernetes CRI reports as the container `imageID`.

Absolute repository and Dockerfile paths remain in the plan for local
forensics, but are excluded from `planDigest`; two hosts with the same source
and build inputs derive the same reproducibility identifier.

The image tag is derived from the build key and the staged source tree. It is a
local transport name, not an acceptance identity. The build record always
keeps `acceptanceReady: false`, even after `kind load`, until an `AttacknetRun`
joins it to the exact admitted Pod UID, declared image, and runtime image ID.
This prevents a mutable tag or an unobserved load from being reported as mixed-
version evidence.

`--load` targets Docker's local image store. Some Docker image stores do not
persist OCI provenance/SBOM attestations on a loaded image. The pipeline
therefore claims only that the separately retained BuildKit metadata contains
maximum-mode provenance and that SBOM generation was requested; it does not
claim a registry-persisted attestation. A later registry workflow must verify
its own attached attestations.

The admission join is exact, but the two relevant digests are not normally
equal. With BuildKit provenance enabled, `imageDigest` identifies an OCI index
containing both the platform manifest and an attestation manifest. Kubernetes
containerd reports the selected platform manifest's **config digest** in
`status.containerStatuses[].imageID`. The executor exports the locally loaded
image as an OCI archive and verifies the complete
`index -> platform manifest -> config` chain. Then
`image-admission-evidence.mjs` binds that expected config digest to an observed
StacksNetwork generation, actor declaration, current Ready Pod UID, and CRI
image ID. A tag match or equality with the outer index digest is never
sufficient.

For a registry-backed cluster, use the immutable index reference. A local kind
cluster without a registry cannot pull an unqualified `repository@digest`
reference merely because the same bytes were preloaded under a tag. In that
case the declaration uses the content-derived local tag with `IfNotPresent`,
and acceptance still requires the exact runtime config digest and Pod UID join.
The tag is transport, not identity.

The existing Dockerfile still defaults to its convenient cargo-chef and Debian
tags for ordinary development. The attacknet pipeline overrides those `FROM`
arguments with digest references and refuses to execute without them. Cargo
Chef remains split into planner/cook/build layers, and release builds retain
`CARGO_INCREMENTAL=0` for stable shared-cache behavior.

Use a dedicated Git worktree for each deliberately modified build. A `current`
or `localModified` profile intentionally captures all tracked and untracked
source files in that worktree; sharing a dirty worktree makes both profiles
represent the same source state.

Profiles may declare a bounded `cargoFeatures` list. The normalized list is
part of the build key, invocation record, and version-matrix provenance, and is
passed identically to Cargo Chef and the final Cargo build. Every attacknet
image retains `monitoring_prom` and `slog_json`; deliberately modified signer
fixtures additionally use the existing `testing` feature. See
[`ADVERSARIAL-ACTORS.md`](ADVERSARIAL-ACTORS.md).

## Live evidence and remaining boundary

After Docker Desktop storage was repaired on 2026-08-15, the pipeline built
release `4.0.2` from exact commit
`1b57c3fb6709ab927f9179ab6814f874c84f5303` for native arm64. The compact
runtime image is approximately 72 MB. Follower-5 was rolled to that image while
the other actors remained on the current branch. The observed generation,
Ready Pod UID, executable version, runtime config digest, full cohort
convergence, and subsequent burn/Stacks progress are retained in
`evidence/mixed-version-4.0.2-follower5-20260815T1840Z/`.

The general live gate is:

1. build all requested profiles and retain their BuildKit metadata/build
   records;
2. load the content tags into the target kind cluster;
3. create the mixed-version topology using those profile assignments;
4. capture the admitted Pod UID, declared image, and runtime image ID;
5. verify the OCI index/platform/config chain, then require the runtime image
   ID to equal the build record's expected **runtime config** digest and bind
   it to the observed generation, actor, and Pod UID;
6. only then run compatibility, missed-upgrade, and modified-actor assertions.

`mixed-matrix-evidence.mjs` is the fail-closed summarizer for that final gate.
Its configuration names the rendered manifest, admitted Pod list, exact build
records, paused-window signer metrics and node snapshots, the modified signer
log, and minimum burn/Stacks progress. It requires immutable runtime joins for
both the released and locally modified actors, preserves the original signer
weights and 70% threshold, proves the modified signer did not validate or
approve proposals, requires healthy signer approvals, and requires the exact
node cohort—including the released actor—to converge at both boundaries.
Validation rejections from otherwise healthy nodes are observations, never
silently attributed to the deliberate adversary.

```sh
node contrib/attacknet/mixed-matrix-evidence.mjs \
  /absolute/path/to/config.json /absolute/path/to/result.json
```

The full 31-workload proof at
`evidence/mixed-current-release-modified-20260816/` ran exact 4.0.2 follower-5
and a source-pinned `reject-all` signer alongside the current cohort. Burn
height advanced 227 to 248, Stacks height advanced 24 to 44, the adversarial
1/25-weight signer rejected all 26 proposals it received, the healthy cohort
emitted 188 accepted responses, and all 18 Stacks nodes converged. The result
digest is bound into the finalized run ledger and authenticated event journal;
the teardown bundle preserves 149,567 centralized log entries and the complete
run finished `passed` before all run PVCs were removed.

The unit tests fake all Docker and kind execution and separately exercise the
OCI identity resolver and admission join. They prove the default path runs no
executor, source drift aborts before a build, kind loading is opt-in, release
refs and base images are pinned, BuildKit provenance is mandatory, index and
runtime config digests remain distinct, stale observed generations fail, and
no build-only result can claim runtime acceptance.
