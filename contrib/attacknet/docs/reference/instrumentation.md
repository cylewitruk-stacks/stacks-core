# Attacknet instrumentation capability contract

Attacknet treats instrumentation as a versioned image capability, not as an
assumption inferred from a tag or an empty Grafana panel. The normative R1
inventory is `instrumentation/inventory-v1.json`. It freezes exactly 22 metric
families, their process roles, types, finite label domains, and maximum series
counts. Counters and histograms reset at process restart; gauges disappear when
the process is not scraped. Block hashes, transaction IDs, identities, URLs,
and free-form errors are never metric labels.

Every image profile assigns every family one of three provenances:

- `merged`: the signal is in the exact upstream source revision used to build
  the image;
- `attacknet-patch`: the signal comes from the recorded patch applied to the
  exact upstream base; or
- `unavailable`: the image does not claim the signal. Missing data is an
  expected capability gap, not zero and not health.

Rendered actor and scrape declarations additionally use `mixed` when the
families applicable to that actor role do not all have the same provenance.
`mixed` is only a bounded summary label. The capability manifest records the
per-family declaration; acceptance additionally requires build-source audit,
admitted runtime identity, and an orchestrator-read metric snapshot.

`instrumentation/workstream-m.patch` is the carried observation-only patch for
the new Workstream M families. M14 (`stacks_signer_block_proposals_received`)
already exists at the upstream base and is always recorded as `merged` when
available; it is not attributed to the patch. The patch was generated against upstream base
`6b002604da0533e69f4ebdceb2747954f496a3ea`, including the M3
proposal-to-first-response review delta. The patch applies cleanly to that
base. When a slice merges, create a new manifest profile from the merged
revision and mark only the merged families as `merged`; do not apply the same
slice again. Mixed provenance is explicit per family.

The patch sidecar records both its byte digest and the exact
`stacks-attacknet-source-state-v1` digest obtained from that base plus those
bytes with no untracked files. Acceptance compilation recomputes this digest
and requires equality with the integrity-bound build record. A different dirty tree at
the same base therefore cannot inherit the patch provenance.

The build record's `instrumentationSourceAudit.familiesPresent` list is an
integrity-bound producer assertion, not an independently derived source-analysis
result. Attacknet verifies its method, inventory, staged-source digest, and
per-family membership, but the instrumentation compiler does not itself parse
the Rust source to rediscover those families. Consequently, this source audit
cannot prove runtime availability on its own. The orchestrator-read, per-actor
runtime metric-presence evidence described below is the authoritative
acceptance proof and must remain mandatory unless a future inventory revision
introduces an independently verified source-audit producer.

M21 intentionally remains two standalone milestones:
`proposal_to_first_response` and `proposal_to_threshold`. There is no claimed
`first_response_to_threshold` distribution in this revision. The dashboards
compare the two distributions diagnostically and explicitly forbid aggregate
percentile subtraction; a future third milestone requires its own direct
observation and inventory revision.

The M19–M21 vector collectors initialize their complete finite valid domains
when node metric serving starts (7, 3, and 4 series respectively). This is
required evidence semantics: a miner that has not coordinated a tenure exports
zero counters/histograms, while an absent family continues to mean that the
runtime capability is unavailable or broken.

The M02 signer outcome vectors follow the same rule. Signer metrics startup
initializes the complete valid domains for policy evaluation, bounded policy
rejection reasons, validation lifecycle outcomes, and response delivery. A
healthy signer with no rejection therefore exports zero-valued rejection
series instead of appearing indistinguishable from an uninstrumented binary.

## Build, admission, and runtime linkage

`instrumentation/capability-manifest.mjs` compiles the inventory and profile
declarations into `stacks-attacknet-instrumentation-capabilities/v1`. For an
acceptance-ready profile it requires:

1. the exact patch contents and upstream base for every `attacknet-patch`
   signal;
2. an integrity-bound `stacks-attacknet-image-build-record/v1`, including source-state,
   build invocation, image-index, platform-manifest, and runtime-config
   digests plus an exact-source audit against this inventory;
3. passing `stacks-attacknet-image-admission-evidence/v1` for every declared
   actor, joining the build record to network UID, Pod UID, and CRI runtime
   image ID; and
4. a passing config-startup smoke for every actor/config used by the profile,
   with the original template digest matching the admitted actor config and a
   separate parser-input digest for substituted placeholders; and
5. an orchestrator-read `/metrics` snapshot for every admitted actor proving
   that every applicable declared family is actually present. Raw snapshots,
   their digests, Pod UIDs, and runtime image IDs are retained together.

The compiler fails `--acceptance` when any link is absent. An offline compile
without that flag remains useful but writes `acceptanceReady=false` and exact
`unresolvedReasons`.

Example input shape:

```json
{
  "schemaVersion": 1,
  "manifestId": "attacknet-r1-run-001",
  "inventoryVersion": "workstream-m/1",
  "profiles": [{
    "id": "patched-main",
    "requestedImage": "stacks-core-attacknet:content-...",
    "actors": [{"name": "miner-1", "role": "miner"}],
    "defaultProvenance": "attacknet-patch",
    "signals": {"M14": "merged"},
    "patch": {
      "path": "instrumentation/workstream-m.patch",
      "upstreamBaseRevision": "6b002604da0533e69f4ebdceb2747954f496a3ea"
    },
    "buildRecordPath": "evidence/patched-main.build-record.json",
    "admissionEvidencePaths": ["evidence/miner-1.admission.json"],
    "configSmokeEvidencePaths": ["evidence/miner-1.config-smoke.json"],
    "effectiveEventDispatchMode": "queued"
  }]
}
```

Compile the immutable qualification result and retain it beside the run and
incident evidence:

```bash
node contrib/attacknet/instrumentation/capability-manifest.mjs input.json \
  --acceptance --output=evidence/instrumentation-capabilities.json
```

The compiler rejects a minimal self-digested assertion that lacks source,
build, admitted Pod, config-smoke, and runtime metric-presence evidence. Build
the admission records from the exact `StacksNetwork.status` inventory and live
Pod `containerStatuses`; requested YAML and image tags are insufficient.

The capability manifest is qualification metadata, not a second runtime
controller. `AttacknetRun` status remains authoritative for schedule and
terminal state, while the capability artifact states which actor metrics may
be interpreted for that run.

The same digest-bound preflight plan supplies the exact per-family provenance
projected by the orchestrator-owned
`attacknet_instrumentation_family_provenance{family,provenance}` metric.
Rendering refuses an available or mixed actor without those expectations, and
the CLI verifies that the plan names and hashes the exact rendered topology
manifest. Provenance is deliberately not attached as 22 scrape-target labels:
doing that would copy every label onto every actor-exported series. Each
family-absence alert joins the bounded metadata metric with actor reachability
and selects only actors whose plan declares that specific family `merged` or
`attacknet-patch`; an actor with mixed provenance is therefore never alerted
for a deliberately unavailable family. The load-bearing metadata path has its
own fail-closed `AttacknetInstrumentationProvenanceExporterAbsent` alert. It
fires after two minutes without provenance series when at least one node or
signer scrape target exists, while intentionally empty topologies do not alert.
Its two-minute hold suppresses startup noise before the first scrape; under the
five-second scrape/evaluation cadence, ordinary stale-marker paths add only
about one cycle rather than the five-minute query lookback.

## Configuration startup smokes

Run `check-config` inside each exact image before interpreting a deployment as
a protocol experiment. Node templates are resolved to numeric loopback
addresses for parsing, but evidence retains both the original template digest
and the sanitized parser-input digest. The original digest must match the
config in the admitted `StacksNetwork`. The live actor entrypoint separately
resolves and strictly validates its runtime IPv4 address before execution.

```bash
node contrib/attacknet/instrumentation/config-startup-smoke.mjs \
  generated/stacksnetwork.json --profile-id=patched-main \
  --image=stacks-core-attacknet:content-... --actor=miner-1 \
  --output=evidence/miner-1.config-smoke.json
```

Repeat for every actor/config used by each image profile. A failed
smoke is configuration incompatibility and stops the experiment before any
protocol conclusion.

## Interpretation guardrails

- Connectivity panels must distinguish authenticated inbound/outbound peers
  from bootstrap or sampled candidates.
- Signer registration and state freshness must be interpreted with its node's
  burn height and the admitted reward-cycle context.
- Event-dispatch mode is part of the actor configuration and must be retained
  with latency evidence.
- A missing series is unavailable evidence, not a zero-valued healthy signal.

## Dashboard interpretation

The network and actor dashboards include instrumentation capability tables.
The aggregate profile is a render-time scrape declaration, while exact family
provenance is emitted centrally by the orchestrator bridge from the
digest-bound qualification plan. Build/admission evidence establishes runtime
identity, while runtime snapshots establish family presence. These JSON
digests provide integrity, not reviewer identity or cryptographic origin
authentication. Actor metric values remain actor-self-reported. Alert rules cover correlated signer participation loss,
frozen signer state, unavailable validation, and Nakamoto propagation failure.
Rules whose metric family is unavailable have no input series and do not imply
health; inspect the capability table and qualified manifest first.

The first-response and threshold histograms are independent aggregate
distributions. Never subtract their p50/p95 values to claim a percentile of
per-proposal weight-accumulation time.

## Offline verification

Offline tests prove the compiler and bounded metric contract only. They do not
replace live image, admission, scrape, and review evidence.

```bash
node --test contrib/attacknet/instrumentation/*.test.mjs
node --test contrib/attacknet/observability/*.test.mjs
bash contrib/attacknet/test/check.sh
# Run from a clean checkout of 6b002604da0533e69f4ebdceb2747954f496a3ea:
git apply --check /path/to/contrib/attacknet/instrumentation/workstream-m.patch
```
