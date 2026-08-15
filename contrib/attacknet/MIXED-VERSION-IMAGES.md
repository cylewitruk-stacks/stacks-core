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
- the resulting image digest and immutable `repository@sha256:...` reference.

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

The admission join is exact: retain the build record's `imageDigest`, read the
admitted Pod's UID, declared image, and `status.containerStatuses[].imageID`,
normalize the image ID to its terminal `sha256:...`, and require equality with
the build digest. The phase assignment and actor name must refer to that same
Pod UID. A tag match alone is never sufficient.

The existing Dockerfile still defaults to its convenient cargo-chef and Debian
tags for ordinary development. The attacknet pipeline overrides those `FROM`
arguments with digest references and refuses to execute without them. Cargo
Chef remains split into planner/cook/build layers, and release builds retain
`CARGO_INCREMENTAL=0` for stable shared-cache behavior.

Use a dedicated Git worktree for each deliberately modified build. A `current`
or `localModified` profile intentionally captures all tracked and untracked
source files in that worktree; sharing a dirty worktree makes both profiles
represent the same source state.

## Current live-test boundary

As of 2026-08-15, Docker Desktop's three kind nodes report zero available root
and image-filesystem bytes through kubelet stats despite remaining Ready. The
attacknet capacity preflight correctly fails closed. No real image build, kind
load, Pod admission, or mixed-version runtime claim has therefore been made.

Once Docker Desktop storage is repaired, the live gate is:

1. build all requested profiles and retain their BuildKit metadata/build
   records;
2. load the content tags into the target kind cluster;
3. create the mixed-version topology using those profile assignments;
4. capture the admitted Pod UID, declared image, and runtime image ID;
5. require the runtime image ID digest to equal the build record's immutable
   image digest and bind that result to the actor and Pod UID;
6. only then run compatibility, missed-upgrade, and modified-actor assertions.

The unit tests fake all Docker and kind execution. They prove the default path
runs no executor, source drift aborts before a build, kind loading is opt-in,
release refs and base images are pinned, BuildKit provenance is mandatory, and
no build-only result can claim runtime acceptance.
