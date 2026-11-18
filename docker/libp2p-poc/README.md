# Stacks libp2p regtest proof of concept

This environment exercises a configurable, libp2p-only Stacks network on one
Bitcoin regtest burnchain. The maximum topology is:

- three independently keyed Stacks miners, each with its own Bitcoin wallet;
- ten Stacks signers, each paired with a distinct non-mining follower node used
  for chain queries and proposal validation;
- five unrelated outsider follower nodes; and
- one isolated, token-attributed OpenTelemetry Collector agent for every node
  and signer process (28 enrolled telemetry actors at maximum scale).

Signer and miner ownership is deliberately separate. A signer uses its own
companion follower for HTTP chain queries and proposal validation. A canonical
sortition-bound role proof—not a configured endpoint—authorizes a miner to
originate proposal traffic. Configured miner endpoints are untrusted rendezvous
and reconnect hints only. Miner proposal manifests and signer envelopes
propagate over the shared authenticated libp2p network; proposal bytes are
fetched as bounded content-addressed objects. All nodes use Noise, Yamux, challenge-
bound Hello, Kademlia discovery, bounded protocol queues, and persistent dial
hints. No incumbent P2P listener or signer StackerDB compatibility writer is
enabled.

The generated topology deliberately does not form a connection clique. Signer
companion nodes and outsider followers are capped at 12 established libp2p
connections; signer processes are capped at 16; secondary miners are capped at
32; the primary bootstrap miner retains a 64-connection recovery ceiling. A
signer reserves six of its sixteen hard-limit slots for three rendezvous PeerIds
(the configured two-connection simultaneous-dial allowance for each).
Identity-aware admission limits restored, discovered, and inbound ordinary
connections to the other ten slots, so they cannot win a race and starve a
rendezvous path. Durable restart recovery proactively dials only eight stored hints
before discovery resumes. These are PoC topology controls, not public-network
recommendations. The library's 300-connection default is a hard safety ceiling,
not a desired peer count; a production target and reserved-peer policy must be
calibrated from reachability, diversity, resource, and propagation measurements.
The hard ceilings count connections, not unique PeerIds. Secondary miners need
additional headroom because every signer pins them and simultaneous dials may
temporarily retain two connections for one PeerId.

The default GossipSub mesh targets six peers with a low watermark of five.
After rendezvous reservation, the signer therefore has only a small amount of
ordinary-connection headroom under churn. Propagation measurements from this
environment intentionally characterize a mesh under pressure and must not be
used as healthy-mainnet calibration data. All actors share one Docker IPv4
/24, so this topology also does not exercise production prefix diversity.

## Run the maximum topology

The wrapper generates all Compose services, TOML files, OTLP receiver routes,
tokens, and observer enrollments from one validated topology model.

```sh
docker/libp2p-poc/poc.sh down --volumes --remove-orphans
docker/libp2p-poc/poc.sh up --build --detach
docker/libp2p-poc/poc.sh verify
docker/libp2p-poc/poc.sh down
```

`verify` can enforce either an explicit absolute burn height or a start-relative
burn-block delta recorded by the soak harness. It briefly pauses Bitcoin block
production and requires every generated Stacks node to converge on the exact
same burn height, Stacks height, and canonical tip ID. It also verifies all
PoX-5 signer contracts/stakes, independent companion validation, bounded native
delivery, persistent peer stores, Epoch 4.0, and complete authenticated
telemetry/observer coverage. Each signer state machine must also remain within
the bounded burn-height drift of its own live companion; the authenticated
observer must contain no persistent signer/companion drift incident. This is a
behavioral delivery assertion, so a syntactically correct but dead or misrouted
`events_observer` endpoint cannot pass. With more than five signers it additionally
requires at least half of them to accept a signer envelope whose immediate
GossipSub propagation peer differs from its signed original source: positive
evidence of real multi-hop mesh delivery, rather than an inference from a
sparse peer count. The transport-mode gate reads each node's live diagnostics
and requires `libp2p-only`, a disabled legacy listener, an `off` signer bridge,
and an enabled persistent peer store; startup log messages are not runtime
state and may age out during a soak. Historical per-actor evidence scans remain
bounded to the latest 10,000 log lines so verification cost does not grow with
the environment's lifetime.

Use smaller counts while iterating; the same ceiling checks and pairings apply:

```sh
POC_SIGNERS=4 POC_MINERS=2 POC_FOLLOWERS=2 \
  docker/libp2p-poc/poc.sh up --build --detach
```

Valid ranges are 1–10 signers, 1–3 miners, and 1–5 outsider followers. Change
counts only with disposable actor volumes or a clean `down --volumes`: genesis
balances and PoX membership are topology-dependent. Generated files live under
`docker/libp2p-poc/generated/` and are intentionally ignored. Run `poc.sh
generate` to inspect them without launching containers. The deterministic keys
and bearer tokens are public regtest fixtures, never deployment secrets.

Set `POC_PROJECT` to run an isolated Compose project. The wrapper always passes
both the infrastructure and generated Compose files, preventing partial
topologies caused by invoking one file directly.

## Observer

Open <http://localhost:4319> and sign in with `user@host.com` / `stacks123`.
Those credentials are a development provider behind the same session boundary
that a future OIDC provider will use.

The anonymous view contains public chain and reward-set data only. The
authenticated federation view aggregates the complete allowlisted metric
catalogue for every enrolled node and signer, endpoint-free topology evidence,
state-machine health, current signer identity/weight, quorum reconstruction,
chain progress, queue pressure, peer counts, and explicit telemetry blind
spots. It joins each enrolled signer to its unique companion and raises a
critical incident when fresh telemetry shows the companion advancing while the
signer state machine remains persistently behind. Public signer keys remain visible, but PeerIds, IP addresses,
multiaddresses, and resolvable endpoints do not cross the federation boundary.

Each actor agent scrapes only its local private Prometheus endpoint and sends
metrics to a dedicated central OTLP/HTTP receiver with a per-actor token. The
receiver route—not a client attribute—establishes identity. The central
collector deletes all client resource attributes, injects the enrolled actor
identity, enforces the exact metric/label allowlist, and exports to bounded
Prometheus retention. Trace federation is structurally absent pending its
separate privacy audit.

## Bounded chaos testing

Chaos is opt-in and host-driven; no privileged container receives the Docker
socket. The runner disrupts at most one allowlisted failure domain at a time:

- one companion node without stopping its signer, proving a bounded
  `ProposalUnavailable` abstention at either canonical-view refresh or
  validation submission, followed by rejoin;
- one signer process without stopping its companion;
- one signer together with its companion node;
- one outsider follower;
- one non-primary miner, or the current tenure miner selected atomically; or
- the telemetry collector; or
- one Bitcoin cadence interval, shortened to a flash block or extended to a
  bounded slow block without stopping bitcoind or changing sortition rules.

It never deletes volumes, stops Bitcoin, or deliberately removes enough signer
weight to destroy quorum. Every event is followed by a mandatory canonical
Stacks transition (height increase or same-height tip replacement) before
another event can begin; Bitcoin progress alone cannot satisfy recovery. If a
disrupted miner owns the current
tenure, the ordinary independent Bitcoin cadence supplies the next sortition;
there is no chaos-only bypass or permission marker in the cadence controller.

```sh
CHAOS_DURATION_SECONDS=300 CHAOS_SEED=42 \
  docker/libp2p-poc/poc.sh chaos
```

For a reproducible focused gate, restrict random selection to an allowlisted
comma-separated subset, for example
`CHAOS_TARGETS=pause:tenure-miner,pause:telemetry-collector`. The special
`tenure-miner` target resolves the current sortition winner at the disruption
boundary, avoiding a cadence race in failover tests. Invalid targets fail closed
before any container is touched.

`cadence:flash` signals the single mining controller to interrupt its current
delay; `cadence:slow` replaces the remainder with
`CHAOS_SLOW_INTERVAL` (90 seconds by default). Cadence events are not considered
recovered until both a subsequent Bitcoin block and a fresh canonical Stacks
transition have been observed. This exercises mainnet-like timing entropy while
keeping mining ownership and the resulting event ledger deterministic.

A companion-only target requests one flash interval immediately after the
companion is paused and repeats that bounded request every 15 seconds until an
abstention is observed or the outage deadline expires. A flash advances only
Bitcoin through the ordinary cadence controller; because it cannot manufacture
a Stacks proposal, several sortitions may be needed before one crosses the
selected signer's canonically-pending path. Counter scrapes are retried under
their own deadline so a transient probe failure cannot silently terminate the
recovery assertion.

The deterministic event/recovery ledger is written to
`generated/chaos.log`. Run `poc.sh verify` after chaos to require exact
canonical convergence and full telemetry recovery. Recovery always performs
both an unpause and a start: Docker Compose may report a successful `unpause`
for a stopped container without starting it. The runner then requires every
recovered service to be running and, where configured, healthy before it may
declare the failure domain recovered.

A companion-only target uses a bounded 90-second deadline by default. That
covers the maximum 60-second cadence-entropy interval plus the generated
15-second signer timeout. The runner ends the outage early once the signer's
`abstained` counter increases, requires its `rejected` counter not to change,
then requires a later accepted companion validation after recovery. This
behavioural wait avoids a false failure when no proposal happens to arrive
during a fixed short outage. Validation POSTs use that same signer deadline and
are not synchronously retried: an unreachable companion therefore produces
`CompanionTimeout` instead of blocking the signer runloop or duplicating
validation work. Companion-derived metric collection uses an independent
five-second RPC deadline on a background refresher; the HTTP server remains
independent and continues serving its last known-good snapshot plus current
process counters during the outage.
Chaos-side RPC probes have their own bounded connect/total timeouts, and the
exit trap always recovers the active target.

For the telemetry-collector scenario, set `CHAOS_OUTAGE_SECONDS=25` and
`CHAOS_ASSERT_BLIND_SPOT=1`. The runner then also authenticates to the observer
while collection is unavailable and requires an explicit
`telemetry-blind-spot` incident before recovery. This proves both halves of the
failure contract: consensus keeps advancing without telemetry, and the portal
does not misrepresent stale samples as a healthy live view.

## Final acceptance soak

`poc.sh soak` is the destructive, clean-volume acceptance harness. It builds the
exact current source, records source checksums and image IDs, starts the maximum
10-signer/10-companion/3-miner/5-follower topology, and measures from the first
healthy-image burn snapshot. It executes deterministic companion-only,
signer-only, combined pair, follower, telemetry, miner, and cadence disruptions;
then it requires at least 300 new burn blocks and at least 30 blocks after the
last disruption before running the full verifier. Final diagnostics, metrics,
tips, health, and chaos ledgers are archived under `generated/evidence/`, and a
successful run tears down containers and disposable volumes.

The soak compares each signer's stable-window lifecycle counters directly from
the actor's Prometheus endpoint. The verifier accepts both the unsuffixed names
emitted by the Rust exporter and the `_total` names produced by OTLP
normalization, compares either spelling when detecting process-stable counter
resets, and enforces the admitted/pending/terminal conservation identity. A
small fixture suite covers both naming forms, reset detection, and failed
conservation so a missing series cannot silently turn runtime evidence into
zeros. The companion-chaos gate separately correlates a released envelope by
its bounded signer signature hash and waits for that exact proposal to reach a
local precommit or a canonical block event. This correlation is archived as
diagnostic runtime evidence because another signer can legitimately
canonicalize first; set `CHAOS_REQUIRE_RELEASE_TERMINAL=1` for a focused run
that requires it. The acceptance gate itself uses behavior-owned counters to
require admission, abstention, release, resumed validation, bounded retries,
and no false companion rejection. Parser fixtures cover each valid ordering
and reject an unrelated proposal's terminal. The final evidence bundle also
contains `released-proposal-classification.jsonl`, a non-blocking classification
of every signer release visible in the run logs. It distinguishes local
precommit, canonicalization before a local vote, and a release with no observed
terminal; a missing or incomplete log correlation is evidence metadata, not a
second stochastic acceptance gate.

```sh
docker/libp2p-poc/poc.sh soak
```

Use `SOAK_KEEP_FAILED_ENV=1` only while diagnosing a failed gate. Reduced block
counts are useful for script smoke tests but do not satisfy final acceptance.

## Mining and restart model

The Bitcoin helper creates one watch-only wallet per Stacks miner, funds each
miner's deterministic P2PKH address in the first blocks, and fast-forwards to
height 202 so all coinbases are mature before the compact epoch schedule. Each
Stacks miner has a different node seed, mining key, VRF path, transport
identity, wallet, and data volume. Multiple block commits may coexist in the
Bitcoin mempool; sortition selects the tenure winner normally.

After bootstrapping, the Bitcoin helper owns a fixed cadence that is independent
of Stacks liveness, matching the public-network dependency direction. It also
observes canonical Stacks height and tip ID: with multiple miners, a sortition
can validly replace the tip at the same height when its winning commit named the
previous parent. That replacement is progress. An unchanged `(height, tip ID)`
for `PROGRESS_STALL_AFTER` is recorded as `stacks-not-advancing`, but Bitcoin
continues to mine and the cadence container remains healthy. The normal
maximum-topology cadence is 20 seconds; this gives the ten-signer state machine
room for one bounded validation retry and is still roughly 30 times faster than
mainnet. The short Epoch 2.x-to-3.0 runway uses a fixed five-second cadence.
Neither cadence waits for a Stacks transition. `verify.sh` independently
requires a fresh canonical transition, so a synchronized but stalled overlay
still fails the verification gate without pretending that Bitcoin itself stopped.

After Epoch 4 activation, ambient timing entropy is enabled by default. A
seeded weighted selector chooses 75% of intervals from 15–25 seconds, 10% from
the 5–14 second flash tail, and 15% from the 26–60 second slow tail. Set
`MINE_ENTROPY_SEED` to replay a run or `MINE_ENTROPY_ENABLED=false` for a fixed
cadence. The chaos runner's explicit `cadence:flash` and `cadence:slow` targets
remain useful when a test must guarantee a particular timing edge case.

Generated miners scale `block_commit_delay_ms` from the public-network
40-second default to one second, below the shortest five-second PoC interval.
This does not relax consensus: Epoch 3+ still requires a miner to commit in at
least three of the last six burn blocks. Without scaling this wall-clock timer,
each accelerated burn arrival can reset a freshly restarted miner before it
submits; all miners can then fail the normal activity rule and the synthetic
five-block PoX prepare phase can end without an anchor. Verification rejects
any mining-frequency winner rejection.

Named volumes support ordinary stop/start. Bitcoin runs with
`persistmempool=0`, because a pre-restart block commit must not outlive the
miner's restored view. Regtest nodes explicitly allow an old persisted Bitcoin
timestamp; public networks retain the normal freshness rule. Changing topology
counts is not an ordinary restart and requires a fresh disposable chain.

On signer restart, each process immediately journals and publishes the state it
reconstructed from its companion node and SQLite database. This avoids a
simultaneous-restart circular wait in which protocol-version agreement needed a
state update, but no signer emitted that update until a later state transition.

Every configured rendezvous peer is maintained as an outbound dial target, but
connectivity never grants miner authority. The canonical winner publishes a
bounded `Role::Miner` proof, and proposal policy independently checks the fetched
block header's recovered miner key. A signed manifest retains semantic ordering,
replay, and equivocation evidence while bounded content fetch supports multiple
providers, relay failover, and current-tenure restart recovery.

The requested stack amounts use deterministic `1,2,3,...` target ratios, but
those ratios are not signer vote weights. PoX assigns integer signer slots from
the current cycle's dynamic threshold. Verification, quorum reconstruction,
and latency calibration therefore consume the effective public signer set and
the miner's round metrics at runtime instead of assuming a fixed total.

Each companion registers its signer for `burn_blocks`, `block_proposal`, and
`stackerdb` events. The signer may start as soon as the companion service has
started, while the companion's durable event worker retries until the signer is
listening; waiting for both processes to be healthy would create a startup
cycle. The soak continuously compares signer state height with its own
companion. This invariant was added after discovering that an earlier generator
call site omitted the observer endpoint: all scaled-run evidence produced by
that configuration is superseded, and final acceptance must cross the former
burn-340 failure point on a fresh image.

The companion's durable burn-block callback can precede query visibility for
the same sortition by a short interval. Before installing native miner
authorization, the signer therefore waits up to two seconds for its own
companion RPC to expose the callback height. This bounded local catch-up closes
the otherwise permanent one-sortition skew without trusting an
envelope-supplied future sortition or creating a network retry loop.

This authorization race is distinct from signer verdicts that reuse the
`SortitionViewMismatch` wire code. The preflight's observed mismatches came
from the v2 active-miner check: the original miner thread exited on the new
burn view, then a distinct old-tenure extension thread raced the new winner's
Stacks block and the signer correctly rejected it. A final burn-tip check alone
cannot distinguish this because the extension thread is already on that new
burn view. The PoC inherits the production 120-second unresponsive-winner
timeout; fresh traces identify the sub-second trigger as the immediate
`BadSortitionWinner` path (`no valid sortition since our last winning
sortition`). Two final-image occurrences resolved to known targets whose commits
were submitted before a newer tenure-start block became canonical, then won a
later Bitcoin sortition: stale-in-flight commits, not processing-lagged unknown
targets. Sparse Stacks propagation cannot widen that submission-to-sortition
window. The PoC produced as many as seven Stacks blocks within one observed
window, so occurrence frequency is environment calibration rather than a
mainnet-rate claim. After any rejected extension, the miner checks
its local canonical Stacks tenure before re-entering assembly and exits if the
new winner is active. Fresh evidence shows this stopping before either the
+5-second or +10-second retry depending on when the local tip advances, without
suppressing the initial extension attempt. The harness preserves the trigger reason,
emission-site message, target, canonical tenure/tip, and node/signer verdicts so a correct
stale-block verdict is not mistaken for authorization lag or multi-hop
delivery latency.

Signer journal repair is coalesced per reward cycle, not per provider. At most
one authenticated provider supplies a page at a time, and page size is derived
as one quarter of the shared signer-event queue capacity. Current and
next-cycle repair therefore reserve at least half the queue for live traffic.
Incomplete pages advance by cursor only after delivery; downstream
backpressure holds the attempt until its refresh deadline, failed providers
rotate with bounded backoff, and identical equivocation evidence is
idempotent. This keeps recovery below the bounded signer-event channel instead
of multiplying identical replay work by the signer-set size.

### The height-1301 failure and the no-shared-validation invariant

The earlier three-signer environment eventually stopped at Bitcoin/burn height
1301 and Stacks height 1194. The shell `read`/`status_line` error visible in the
combined container history was a previously fixed readiness-probe race, not the
terminal cause.

The live node had emitted roughly 6.9 million retry/resource-rejection events
versus only thousands of real sync requests. The old remote-validation result
path could reschedule immediately under backpressure and starve signer work.
That subsystem has now been removed, not optimized: each signer submits only to
its own companion and accepts only its exactly correlated callback. Companion
failure abstains; it never becomes invalidity evidence. `ProposalUnavailable`
is capability-negotiated, direct-only liveness evidence. It cannot trigger a
loop-speed retry or clear genuine rejections: the miner waits the existing
escalating deadline and clears only temporary unavailable state.

Ten independent companion executions are the security baseline, not a 10×
regression. Reintroducing cross-signer validation coalescing would recreate a
single validation authority and is explicitly out of scope for optimization.

Signer public keys in generated observer enrollment are derived from the exact
private scalars written to signer configuration. They are not independently
maintained literals; generated telemetry identity, on-chain reward-set identity,
and the running signer therefore cannot silently diverge.

Initial block download always includes the highest-ranked authenticated
provider in its status hedge and rotates the remaining slot across other
eligible peers. The configured bootstrap is ranked as a recovery anchor. This
prevents a maximum-scale simultaneous start from diluting the populated source
among many valid but still-empty peers. Preference is not trust: the bootstrap
must complete Noise and Hello, advertise the required capabilities, and remains
subject to response validation, availability backoff, and invalid-data
quarantine.

An authenticated `Busy` reply is treated as short-lived overload rather than
as peer unavailability. Retry phases are deterministically jittered by the
requester's local identity and request correlation, so simultaneous startup of
all generated nodes does not repeatedly admit the same subset into the bounded
sync queue. The queue remains deliberately small; scale support does not depend
on converting a count bound into a large attacker-controlled memory reserve.
If the shared downstream handoff is already full, one already-validated,
metadata-only sync-control request per authenticated peer may wait in a
separate 64-entry FIFO for at most two seconds. This includes status and the
bounded PoX, Epoch 2.x, tenure, mempool, and attachment inventory pages needed
to advance one coherent plan. Objects, signer replay, block
proposals, and arbitrary payloads cannot enter it. This gives every plan fair
forward progress without granting a bulk-data memory bypass.

`GetStatus` is a state snapshot, not a block-processing event. Its Stacks tip
therefore comes from the durable canonical sortition index rather than the
current peer-thread pass result. The latter contains only changes produced by
that pass and is legitimately empty most of the time; treating it as durable
state made a populated bootstrap intermittently advertise a genesis tip. Under
maximum-scale startup, only the few clients whose probe happened to overlap a
block-processing pass would begin IBD. The durable snapshot closes that timing
dependency, while response validation and provider quarantine remain
unchanged.

Only status discovery is hedged across providers. Once a current status wins,
all pages and object IDs in that sync plan remain affine to the same provider.
If it becomes busy or unavailable, the client returns to status discovery and
selects another coherent source. This prevents a valid empty inventory from a
behind hedge being combined with a plan established by an ahead peer.

## Epoch schedule and signer bootstrap

The compact schedule enters Epoch 3.0 at burn 223 and Epoch 4.0 at 245. The
stacker service registers all configured keys in PoX-4 and deploys the local
sBTC interface fixtures as soon as Epoch 3 begins, matching the historical era
in which those public contracts existed. This leaves a full settlement window
before Epoch 4 instead of making activation race a just-in-time deployment. It
then independently
deploys/registers/stakes every signer through PoX-5. A gate before cycle 13's
prepare phase requires all selected accounts to be locked. PoX-5 stakes are
renewed before their bounded 96-cycle horizon expires rather than silently
allowing an empty signer set.

Fixture deployments explicitly use Clarity 2 and are retried from the latest
account nonce until the contract is actually readable. This matters on a
persisted restart: the HTTP listener can become healthy before the node has
replayed its chainstate past Epoch 2.5, and receiving a transaction ID is not
proof that the transaction entered the canonical mempool.

The image uses the `libp2p-poc` Cargo profile for iteration speed. It is not a
production build profile. `libp2p-only` describes node peer transport, not an
HTTP-free signer: every signer still uses authenticated RPC to its companion
node for local chain queries.
