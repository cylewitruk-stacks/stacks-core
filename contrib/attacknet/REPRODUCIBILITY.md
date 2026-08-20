# Attacknet reproducibility contract

`run-descriptor.mjs` records enough resolved input and ordered evidence to retry a
run without pretending Kubernetes, networks, clocks, or proof-of-work are fully
deterministic. The descriptor is an integrity-sealed JSON document using schema
`stacks-attacknet-run/v1`.

It records:

- a caller-supplied run ID, seed, and named seed/decision algorithm;
- exact source revision, plus a patch digest when the worktree is dirty;
- raw-file SHA-256 digests for topology, rendered configuration, and the
  runtime-admitted Kubernetes or Compose manifest;
- both requested image references and runtime-resolved image digests;
- a contiguous ledger of fault decisions, cadence changes, and assertion results;
- an explicit disclosure of remaining nondeterminism; and
- a digest of the complete descriptor itself.

For Kubernetes, the admitted manifest must be captured from the API server, not
copied from the requested YAML, and image digests must come from running Pod
status. For Compose, resolution captures `docker compose config` plus exact
container inspections, requires one Running container per actor service, verifies
the requested image reference, and records the immutable Docker image ID. Store
all referenced artifacts beside the descriptor in the evidence bundle;
`validate --verify-files` then detects missing or modified inputs.

Runs that claim Phase 1 instrumentation attach the acceptance-ready capability
manifest after image admission and before finalization:

```bash
node contrib/attacknet/run-descriptor.mjs instrumentation "$RUN_DESCRIPTOR" \
  --manifest=evidence/instrumentation-capabilities.json
```

The attachment preserves the capability-manifest digest and profile IDs beside
the topology, configuration, admitted manifest, and resolved image inputs. An
offline or incomplete capability manifest is rejected rather than being
recorded as acceptance evidence.

Schema v1 predates the Compose backend and retains the field name
`inputs.kubernetes` for this backend-neutral resolution slot. The nested
`resolution.backend` is authoritative (`kubernetes` or `compose`). A future v2
can rename the field to `inputs.runtime`; sealed v1 evidence must not be silently
rewritten.

## Commands

Create metadata JSON with the fields below, then initialize the ledger:

```json
{
  "runId": "nightly-20260815-001",
  "seed": "18446744073709551615",
  "seedAlgorithm": "agent-decisions/v1",
  "createdAt": "2026-08-15T01:00:00Z",
  "sourceRevision": "a7e3e76019d9",
  "sourceDirty": false,
  "topologyPath": "evidence/topology.json",
  "configPaths": ["evidence/stacksnetwork.json"],
  "admittedManifestPath": "evidence/admitted-resources.json",
  "images": [{
    "scope": "stacks-actors",
    "requestedRef": "stacks-core:main",
    "resolvedRef": "stacks-core@sha256:...",
    "resolvedDigest": "sha256:..."
  }],
  "nondeterminism": {
    "statement": "Scheduling and packet timing remain nondeterministic.",
    "disclosed": [{
      "source": "kubernetes-scheduling",
      "impact": "Actor placement changes resource contention and timing.",
      "capture": "Admitted resources and pod placement are retained.",
      "bounded": false
    }]
  }
}
```

```sh
node contrib/attacknet/run-descriptor.mjs init evidence/run.json --metadata=evidence/run-metadata.json
node contrib/attacknet/run-descriptor.mjs resolve evidence/run.json --resolution=evidence/resolution.json
node contrib/attacknet/run-descriptor.mjs append evidence/run.json --event=evidence/next-event.json
node contrib/attacknet/run-descriptor.mjs finalize evidence/run.json --status=failed
node contrib/attacknet/run-descriptor.mjs validate evidence/run.json --verify-files
node contrib/attacknet/run-descriptor.mjs minimize evidence/run.json evidence/replay.json
node contrib/attacknet/run-descriptor.mjs choose evidence/run.json campaign-target 42 miner-1 miner-2 miner-3
```

Events use `fault-decision`, `cadence-transition`, or `assertion-result` as their
`type`; include `occurredAt` and a type-specific `payload`. Append operations assign
the contiguous `sequence`. They must be serialized by the run controller and
supplied in causal order. `recordedAt` defaults to the recorder clock and is kept
separate from `occurredAt`.

Initialization normally happens before runtime apply. In that mode metadata
uses `requestedManifestPath`, and image entries contain only `scope` and
`requestedRef`. After the network is Ready, Kubernetes `resolve` supplies the
API-server-admitted manifest and Pod image identities; the Compose lifecycle uses
`run-ledger.mjs resolve-compose` to supply the resolved Compose model and exact
container image IDs. A run cannot finalize as `passed` while this resolution is
incomplete. Failed or aborted bootstrap attempts retain an explicit incomplete-
resolution record rather than losing their evidence or blocking teardown.

`minimize` selects the first failed/errored assertion by default, or the named one
with `--assertion=ID`. It emits a planned replay containing the original seed and
immutable inputs plus only fault and cadence actions preceding that failure. Action
offsets are relative to the first retained action. This is safe, deterministic
**prefix minimization**, not proof of causal minimality; use subsequent successful
replays and delta debugging before attributing a minimal cause.

`choose` makes an HMAC-SHA256 choice from the descriptor seed, a stable
instruction namespace, an explicit index, and an ordered set of choices. It
returns the selected index and digest so an agent's branch decision is
independently reproducible. Namespaces and indices describe scenario
instructions; they must not be incidental loop positions that change when an
unrelated step is inserted.

The seed is an instruction to the named decision algorithm, while the recorded
fault-decision ledger is the resolved truth. An agent should prefer replaying those
resolved decisions over rerunning an underspecified random generator. A run is not
reproducible when its nondeterminism disclosure is missing, even if all assertions
passed.
