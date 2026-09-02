# Mixed-version networks and upgrades

A version profile binds source, build inputs, one immutable runtime image,
optional configuration, instrumentation capabilities, and a compatibility
hypothesis. Attacknet resolves profiles and actor assignments on the host;
controllers never clone repositories or run builds.

## Supported source kinds

| Kind | Author input | Sealed result |
| --- | --- | --- |
| `remoteGit` | Repository plus tag, branch, or SHA | Credential-free repository identity, exact commit and tree, submodules, build and image digests |
| `localGit` | Checkout plus optional ref | Exact commit and tree, dirty-patch and untracked-content digests, build and image digests |
| `prebuilt` | OCI reference containing `@sha256:...` | Selected platform and runtime image identity |

Mutable refs are authoring conveniences. Replay uses the descriptor's exact
commit and image, never a branch, tag, or mutable image tag.

## Prepare and load profiles

Start from [`stable-with-candidate.plan.yaml`](../../examples/matrices/stable-with-candidate.plan.yaml).
From the repository root:

```bash
ATTACKNET=/tmp/stacks-attacknet

$ATTACKNET version prepare \
  --file contrib/attacknet/examples/matrices/stable-with-candidate.plan.yaml \
  --workspace .attacknet/version-workspace \
  --recipe-root . \
  --output .attacknet/stable-with-candidate.json

$ATTACKNET version load \
  --descriptor .attacknet/stable-with-candidate.json \
  --mode require
```

Preparation is an explicit trusted host action. A selected source tree may run
Dockerfile, Cargo, dependency, or build scripts; do not prepare untrusted
repositories merely because Kubernetes actor Pods are sandboxed.

`build.dockerfileScope: host` selects a Dockerfile beneath `--recipe-root`
while keeping the chosen revision as the Docker build context. This is the
normal path for releases that predate Attacknet's current image recipe. Use
`source` only when the selected revision intentionally carries its own
Dockerfile. The exact recipe bytes and scope are part of the build-input
digest.

The descriptor records the assignment algorithm, seed, ordered actor set,
explicit overrides, weighted rules, and final actor-to-profile mapping. The
same input produces the same mapping. Controllers consume only the explicit
result.

R1 seals the canonical build inputs, selected platform's runtime config
digest, and verified import on every local kind node. It does not yet export a
portable builder-toolchain, OCI index/manifest, or base-layer inventory;
registry-backed publication is required for that stronger cross-host claim.

## Static missed-upgrade topology

Apply a descriptor to a v1beta1 `StacksNetwork` before submission:

```bash
$ATTACKNET version render-static \
  --descriptor .attacknet/stable-with-candidate.json \
  --network contrib/helm/hacknet/examples/mixed-versions.yaml \
  > .attacknet/mixed-network.yaml

$ATTACKNET submit --namespace hacknet-system \
  --file .attacknet/mixed-network.yaml
```

The rendered network carries a bounded runtime manifest. The topology operator
reports each admitted Pod UID and runtime image ID; the
orchestrator metric bridge joins those trusted values to the source revision,
profile, provenance digest, config digest, capability set, and expectation.
Image tags alone never prove the cohort.

## Rolling upgrades

Render the descriptor's typed `UpgradeCampaign`, submit it as a template, and
schedule it through `AttacknetRun`:

```bash
$ATTACKNET version render-upgrade \
  --descriptor .attacknet/stable-with-candidate.json \
  --namespace hacknet-system \
  --template=true \
  > .attacknet/roll-candidate.yaml

$ATTACKNET submit --file .attacknet/roll-candidate.yaml
$ATTACKNET submit \
  --file contrib/attacknet/examples/runs/mixed-version-boundary-upgrade.yaml
$ATTACKNET wait --for terminal AttacknetRun mixed-version-boundary-upgrade
```

An `UpgradeCampaign` contains cumulative stages. Each stage has a stable
window, deadline, optional protocol assertions, and actor assignments bounded
by parallelism, signer-weight, and miner-percentage limits. The topology
operator remains the only StatefulSet writer. The upgrade controller admits
the baseline and observes exact before/after inventories. With
`rollbackOnFailure: true`, it restores the baseline before reporting `Failed`
or `Inconclusive`; otherwise it preserves the failed deployment for triage
until campaign cleanup rolls it back.

Pass `--template=false` only when submitting an `UpgradeCampaign` directly;
the default is an inert template suitable for an `AttacknetRun` catalog.

One `AttacknetRun` may execute one upgrade campaign. Put all rollout batches
inside that campaign's stages; this prevents two persistent overlays from
competing. A trusted run trigger can place the transition at a burn height,
Stacks height, elapsed time, or finite observation. Epoch and reward-cycle
scenarios use an exact burn height derived from the admitted burnchain policy.

## Configuration compatibility and drift

Omitting an actor/profile configuration preserves the actor's current
`StacksNetwork` configuration. When a version cannot parse that configuration,
provide a complete raw ConfigMap or Secret-backed file as shown in
[`raw-config-fallback.plan.yaml`](../../examples/matrices/raw-config-fallback.plan.yaml).

Preparation hashes the exact file and either:

- runs the supplied command in the target image with no network, a read-only
  root filesystem, bounded CPU, memory, PIDs, and temporary storage; or
- records the operator's explicit `allowUnverified` exception.

For externally prepared objects without a local file, `expectedDigest` is
mandatory. At runtime a restricted, credential-free init container hashes the
mounted ConfigMap or Secret key before the actor starts. A mismatch keeps the
Pod unready, causing a rolling stage to time out and roll back. The operator
therefore does not need permission to read Secret content.

A profile identifies one executable build. The plan's `configurations` list
binds raw config independently by actor and profile, so miners, signer nodes,
and signers may share one build while retaining distinct configuration. A
profile-level configuration remains available as a default for homogeneous
cohorts; the actor/profile entry takes precedence.

Configuration parsing, process startup, protocol compatibility, and telemetry
availability are separate outcomes. A parser or smoke failure is
`ConfigurationUnsupported`; missing metrics cannot establish
`ProtocolIncompatible`.

## Evidence and interpretation

For every actor, retain:

1. requested repository/ref or immutable prebuilt image;
2. exact commit, tree, submodules, dirty and untracked digests;
3. Dockerfile, build-input, built-image, and config digests;
4. deterministic assignment receipt;
5. admitted network generation, Pod UID, requested image, and runtime image ID;
6. upgrade inventory transitions and protocol assertion outcomes; and
7. the finite capability set used to interpret missing metrics.

Grafana's version table and rolling-upgrade timeline are human views over this
data. Review and replay use the canonical descriptor, controller status, and
incident evidence directly.
