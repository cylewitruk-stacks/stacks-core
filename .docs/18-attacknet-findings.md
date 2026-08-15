# Attacknet findings ledger

This ledger records pains and reliability, liveness, security, and operability
findings surfaced while bringing the current-main Stacks stack into the
Kubernetes attacknet. It deliberately includes harness defects: trustworthy
experiments require the apparatus to fail visibly and converge exactly.

## Classification

- **Upstream candidate**: behavior in today's Stacks/Signer code that may merit
  a standalone issue or fix.
- **Harness defect**: attacknet/operator behavior that can invalidate evidence.
- **Environment prerequisite**: a condition the preflight must measure and
  report, rather than misclassifying the resulting failure as a Stacks bug.
- **Resolved extraction mismatch**: branch/Compose assumptions removed while
  porting to current main.

## F-001: Docker Desktop's shared VM disk can be full while Kubernetes reports no DiskPressure

- Classification: environment prerequisite
- State: mitigation implemented manually; automated kubelet-filesystem
  preflight implemented and pending capacity-run verification
- Evidence: Bitcoin Core exited before writing regtest genesis with `Disk space
  is too low`; its new PVC contained 296 KiB and was Bound. The worker reported
  `DiskPressure=False`, while `df` inside the kind worker showed its shared
  95 GiB `/var` filesystem at 100%. Docker reported 17.92 GB of entirely
  reclaimable build cache. Pruning only unused build cache restored 12 GB free.
- Risk: a harness can attribute an infrastructure-capacity failure to Bitcoin,
  or enter CrashLoopBackOff before any experiment starts.
- Required action: capacity preflight must record filesystem free bytes from
  every kind node and fail early below a documented floor. Evidence must retain
  both Kubernetes conditions and actual filesystem capacity because they can
  disagree.

## F-015: Local kubectl is outside the supported client/server version skew

- Classification: environment prerequisite / tooling ambiguity
- State: recorded; matching-client packaging remains open
- Evidence: the local client is Kubernetes 1.34 while the reset Docker Desktop
  cluster is 1.36. Every version query warns that the difference exceeds the
  supported minor-version skew of plus or minus one.
- Risk: a failed command can be misclassified as an operator or CRD defect when
  its client serialization/behavior is unsupported by the API server version.
- Required action: capture both versions in every run descriptor and evidence
  bundle, warn or fail in strict preflight when skew exceeds one minor, and
  provide a matching kubectl through the attacknet tool image or documented
  local prerequisite.

## F-016: Nakamoto block ingress is absent from current-main node metrics

- Classification: production and attacknet observability gap
- State: confirmed in current main; bounded instrumentation pending
- Evidence: `stacks_node_stx_blocks_received_total` increments for legacy
  `StacksMessageType::Blocks`, while the `StacksMessageType::NakamotoBlocks`
  receive path has no receive counter. Existing tip-height and processed-block
  metrics show aftermath, not whether or how Nakamoto payloads arrived.
- Risk: during propagation or liveness incidents, a human cannot distinguish
  delivery failure from delayed processing through metrics alone. The gap is
  especially harmful in an adversarial network where receipt, validation,
  relay, and adoption are separate hypotheses.
- Required action: add bounded Nakamoto receive/serve/relay counters (with only
  low-cardinality source/outcome dimensions), expose them in the attacknet
  propagation dashboard, and retain logs/traces for per-block correlation.

## F-017: `private_neighbors=true` expands actor data-plane reach by design

- Classification: attacknet security boundary
- State: accepted for the isolated private cluster; network-policy control pending
- Evidence: the setting is required for kind Pod-to-Pod legacy P2P, but it also
  disables private-address filtering in peer registration, neighbor discovery,
  mempool sync, and StackerDB sync. A malicious actor may therefore advertise
  or attempt private/internal destinations.
- Risk: copying this profile outside an isolated attacknet could expose internal
  services or let malicious experiments reach the Kubernetes/API control plane.
- Required action: never present the option as a production default. Keep actor
  Pods credential-free and isolated; add scenario-aware egress NetworkPolicy
  that always protects the Kubernetes API/operator/control plane while allowing
  actor Pod CIDRs, DNS, Bitcoin, and deliberately selected adversarial targets.

## F-018: Capacity convergence was incorrectly sampled as an instantaneous invariant

- Classification: harness rigidity / false-negative finding
- State: fixed with a bounded, evidence-preserving convergence gate
- Evidence: stage one became Kubernetes Ready, released its 20-second Bitcoin
  cadence, and was sampled roughly five seconds later. All nodes correctly
  agreed at Stacks height zero, so the new nonzero-height invariant failed and
  aborted the entire capacity series before the first scheduled burn block.
- Risk: strict but mistimed assertions classify expected bootstrap latency as
  a protocol failure and make the harness sensitive to scheduler luck.
- Required action: poll strict invariants within an explicit convergence
  deadline. Preserve every failed attempt, the winning attempt, and attempt
  count so a slow-but-passing run remains visibly different from a fast pass.

## F-019: Post-activation actor readiness formed a cycle with paused cadence

- Classification: harness orchestration deadlock
- State: activation-aware lifecycle implemented; live verification pending
- Evidence: in the medium topology, miner 2 intentionally waited for burn
  height 223 before starting. The operator correctly reported 14/15 Ready, but
  lifecycle waited for 15/15 before releasing a Bitcoin clock paused at 202.
  Therefore the activation condition could never become true.
- Risk: delayed joins, upgrade-at-height scenarios, and future scheduled
  adversaries can deadlock before the experiment begins; a long startup timeout
  merely hides the causal cycle.
- Required action: record activation gates in the backend-neutral manifest.
  Wait only for the ungated bootstrap cohort, advance Bitcoin through policy at
  an explicit fast bootstrap cadence, require the full cohort after activation,
  then restore the requested steady cadence. Record every transition for replay.

## F-020: Node `require()` is not a general JSON-file reader for relative paths

- Classification: harness portability defect
- State: fixed
- Evidence: activation-aware lifecycle passed a relative evidence-tree manifest
  to `require(process.argv[1])`; Node treated the path as a package specifier and
  failed with `MODULE_NOT_FOUND`. Absolute paths happened to work in prior ad
  hoc runs, hiding the assumption.
- Risk: identical rendered inputs behave differently depending on the caller's
  path spelling, aborting runs after resources are already created.
- Required action: read caller-supplied artifacts explicitly through `fs` and
  parse JSON. Reserve `require()` for actual modules, and test lifecycle entry
  points with relative as well as absolute evidence paths.
- Recurrence: the first Chaos Mesh campaign found six remaining instances in
  `campaign-runner.sh` and three in timeline export before any fault was
  injected. The check suite now rejects this pattern across all attacknet
  shell/JavaScript sources so it cannot migrate to another entry point.

## F-021: Shared network labels made observability deadlock actor activation

- Classification: harness accounting defect
- State: fixed; clean capacity rerun required
- Evidence: the activation-aware bootstrap gate compared the number of Pods
  carrying `testing.stacks.org/network` with the actor-only workload count in
  the topology manifest. Enabling Prometheus, Grafana, and the event journal
  produced 18 network-labelled Pods for a 15-actor manifest, so the equality
  could never hold and Bitcoin correctly remained paused at height 202.
- Risk: adding trusted instrumentation can silently change experiment control
  flow. A run then appears to expose a protocol bootstrap failure even though
  the harness is waiting on incompatible resource populations.
- Required action: inventory actors by the server-enrolled actor identity label
  (`testing.stacks.org/actor`), inventory observability separately, and keep all
  readiness/accounting denominators explicit in evidence and dashboards.

## F-022: Delayed actors inherited a Compose-only discovery name

- Classification: backend portability defect
- State: fixed; clean capacity rerun required
- Evidence: Bitcoin advanced beyond the configured burn-height gate and the
  source miner reported burn 240, but `miner-2` remained in its join loop. The
  script defaulted to `miner-1`, valid Compose DNS; Kubernetes exposes the same
  actor as `<network>-miner-1`. An in-Pod request to the scoped Service returned
  the expected activation height immediately.
- Risk: upgrade-at-height and missed-upgrade experiments can remain silently
  gated, so a version under test appears absent rather than incompatible. DNS
  and endpoint assumptions are part of a version profile's executable contract.
- Required action: inject the backend-resolved source Service through an actor
  environment variable, test both renderers, and record resolved endpoints in
  the admitted run descriptor.

## F-023: Failure evidence capture aborted on the failed actor

- Classification: forensic harness defect
- State: fixed and live negative control passed
- Evidence: capture of the F-022 state stopped at the first unavailable
  `/v2/info` endpoint under `set -e`, precisely because the delayed actor had
  not started its RPC server. Admitted Kubernetes state was preserved, but the
  remaining metrics and logs were skipped.
- Risk: the most causally useful evidence disappears in the runs that need it.
  This violates the attacknet's freeze/preserve/explain contract and can turn a
  reproducible product defect into an unactionable red build.
- Required action: make every actor probe bounded and independently fallible,
  write explicit error markers rather than empty files, capture live peers and
  diagnostics alongside tips, and prove the collector completes with one or
  more deliberately unreachable actors.
- Verification: the collector subsequently completed across all 15 actors with
  `miner-2` RPC deliberately unavailable, preserving 12 metric snapshots, 18
  bounded logs, runtime state, and explicit JSON error markers for all three
  failed miner probes.

## F-024: Kubernetes resource usage had no Metrics API

- Classification: local-cluster capability gap
- State: open; kubelet summary fallback is available but not dashboarded
- Evidence: `kubectl top pods` returned `Metrics API not available` on the
  three-node Docker Desktop kind cluster, while authenticated kubelet summary
  calls returned per-Pod CPU, memory, filesystem, placement, and inode data.
- Risk: a campaign can pass protocol invariants while one actor exhausts a
  worker, and humans cannot correlate protocol degradation with contention in
  the primary dashboard.
- Required action: capture kubelet summaries at every stage regardless of
  metrics-server availability. Decide explicitly between installing
  metrics-server and granting a trusted, non-actor resource observer narrowly
  scoped node/proxy access; never give this authority to adversarial actors.

## F-025: Progress verification emitted concatenated JSON documents

- Classification: forensic evidence defect
- State: fixed; rerun required
- Evidence: the successful companion-failure campaign wrote the network cohort
  object followed immediately by the burn-progress object to one `.json` file.
  Shell exit status proved both checks passed, but no JSON parser could consume
  the artifact as a single document.
- Risk: automated triage, report generation, replay minimization, and later
  audit cannot reliably interpret a result that was only human-readable in the
  live terminal.
- Required action: emit one schema-shaped result containing `{ok, cohort,
  progress}` and validate every evidence JSON file before a run is finalized.

## F-026: Recovery duration included the post-recovery observation window

- Classification: observability semantic defect
- State: fixed; rerun required
- Evidence: the companion became healthy on the first post-clear verification,
  but `recovery.complete` reported 41 seconds because its clock stopped only
  after a subsequent 30-second burn-progress check.
- Risk: recovery SLOs appear slower as the verification window becomes more
  rigorous, making the metric measure harness policy rather than system repair.
- Required action: record clearance-to-health immediately when recovery
  invariants pass; report post-recovery progress as a distinct assertion and
  retain both timestamps in the incident timeline.

## F-027: Bitcoin-only progress produced a false healthy/recovered result

- Classification: harness false-pass and attribution defect
- State: fixed in the shared verifier; preserved stalled run is the negative control
- Evidence: the first full 31-workload run advanced bitcoind from height 1287
  to 1288 during a 25-second verification window while every one of the 18
  Stacks nodes remained at Stacks height 17. The old progress invariant
  inspected only `bitcoin-cli getblockcount`, so the companion fault campaign
  was initially labelled recovered even though Stacks had stalled before the
  fault was injected.
- Risk: external-chain progress can conceal a completely halted Stacks network,
  contaminating every recovery claim and making the injected fault appear
  causal when it is not.
- Required action: temporal progress now requires both the configured burnchain
  delta and a cohort-wide minimum Stacks-tip delta. It captures start and end
  cohorts, preserves both dimensions in the result, emits failed evidence before
  exiting nonzero, and must remain a deliberate negative control.

## F-028: A signer private key and funded genesis address diverged

- Classification: topology fixture defect with protocol-liveness impact
- State: root-caused and fixed; clean-run validation pending
- Evidence: zero-based signer 9 used private key `4a…4a01`, which independently
  derives testnet address `ST3MWT31K0SX74MHJCEWGZY5MR05X61FC5HEVK3W1`.
  Genesis instead funded `ST350FBN4H0EKWQCW6BTFK97RGXFS5QJ78E9NST20`.
  The latter retained its full unlocked genesis balance; the derived address had
  zero. The stacker logged the insufficient balance before the chaos campaign,
  retried indefinitely, and miners later reported no canonical PoX anchor.
- Risk: a typographical identity-fixture error can admit a full topology, mine a
  few Stacks blocks, then halt at a protocol boundary. Without preserved timing,
  it is easily misattributed to the first subsequent fault.
- Required action: fund the derived address, pass the expected funded addresses
  to the stacker, and fail immediately if any private key derives a different
  address. The topology test also asserts that every expected address appears in
  every miner's genesis balances.

## F-029: Zero unauthenticated conversations is too strict for an adversarial baseline

- Classification: harness rigidity / false-failure finding
- State: fixed in the baseline connectivity invariant
- Evidence: one snapshot saw signer companion 10 with 32 authenticated and one
  unauthenticated conversation; 25 seconds later it had 32 authenticated and
  zero unauthenticated. Requiring the latter count to be identically zero made
  the starting cohort fail on a normal in-progress handshake.
- Risk: an unauthenticated scanner or malicious handshake can fail every run on
  demand, turning a useful signal into a denial of the test harness itself.
- Required action: baseline connectivity requires at least one authenticated
  live inbound/outbound conversation per node and records the unauthenticated
  maximum. Separate bounded rate, age, and resource-pressure assertions—not
  mere presence—must classify handshake abuse.

## F-002: Branch-only config fields make current-main actors fail at startup

- Classification: resolved extraction mismatch
- State: fixed in the current-main topology renderer
- Evidence: current main rejected `burnchain.allow_stale_bitcoin_tip` as an
  unknown field. The value came from the libp2p development branch.
- Risk: mixed-version experiments can accidentally test config incompatibility
  instead of protocol compatibility.
- Required action: render profiles by binary/version and add a config-startup
  smoke for every image used in a mixed-version campaign.

## F-003: Legacy P2P advertised addresses require numeric sockets

- Classification: resolved extraction mismatch; upstream diagnostics candidate
- State: fixed in the attacknet with runtime container-IP substitution
- Evidence: a Kubernetes Service DNS name in `node.p2p_address` passed initial
  config loading but later panicked in `StacksNode::setup_peer_db` with `Failed
  to parse socket`. `connection_options.public_ip_address` failed earlier with
  a normal config error for the same DNS form.
- Risk: Kubernetes and other dynamic schedulers cannot embed ephemeral Pod IPs
  in static config, and the two related fields fail at different phases—one by
  process panic.
- Required action: the harness resolves and substitutes the runtime IPv4 into a
  writable config. Consider an upstream issue to validate `node.p2p_address`
  during config parsing and return a structured error instead of panicking.

## F-004: Signer/companion startup has an intentional cyclic relationship

- Classification: harness defect exposed by topology port
- State: fixed in the topology model; live verification in progress
- Evidence: the companion's durable event dispatcher must reach the signer
  before companion RPC becomes Ready, while a signer init gate waiting for that
  RPC prevents the signer event server from starting. The prior Compose harness
  explicitly used `service_started` and documented that the signer node client
  retries while the companion boots.
- Risk: translating `depends_on` mechanically into readiness/TCP gates creates
  a permanent simultaneous-start deadlock and invalidates restart tests.
- Required action: start signers concurrently, publish signer endpoints before
  readiness, retain explicit cycle diagnostics, and keep per-edge startup gates
  separate from target Service endpoint publication.

## F-005: StatefulSet merge-patch retains removed dependency init containers

- Classification: harness defect
- State: fixed by rendering an explicit empty `initContainers` list; broader
  exact-convergence audit remains open
- Evidence: the admitted signer actor had `dependencies: []`, and the local
  resource builder rendered no init container, but the live StatefulSet kept
  the previous `wait-for-dependencies` entry because JSON merge-patch preserves
  omitted fields.
- Risk: the operator can report the latest CR generation as observed while a
  stale execution constraint remains active, producing false evidence.
- Required action: explicitly clear removable list/map fields and audit every
  merge-patched resource field for the same omission semantics. Longer term,
  adopt a deliberate exact-reconciliation strategy (careful replace, JSON
  patch diff, or server-side apply ownership) rather than relying on omission.

## F-006: Runtime endpoint publication and startup gates are different controls

- Classification: harness design finding
- State: first-class `runtimeExposure: ready|reachable` implemented
- Evidence: `publishNotReadyAddresses` belongs to the target Service, whereas a
  dependency wait belongs to an incoming edge. One target cannot implement two
  callers' different gate semantics through a single Service readiness flag.
- Risk: conflating the controls either forbids realistic reachable-but-broken
  states or creates accidental bootstrap cycles. Endpoint withdrawal also does
  not disrupt established P2P connections.
- Required action: preserve target-level runtime exposure as a discovery knob;
  implement per-edge startup gates separately; use Chaos Mesh/process controls
  for established-connection faults.

## F-007: Cadence must not advance protocol boundaries during harness bootstrap

- Classification: harness defect / policy-orchestration finding
- State: fixed for fresh Kubernetes runs; clean-volume verification pending
- Evidence: while config and dependency failures were being repaired, the
  independent Bitcoin clock continued from its base height through multiple
  protocol boundaries. Bitcoin reached 250, while all Stacks nodes repeatedly
  processed burn 241 with `Missing canonical anchor block`; the miner had three
  Stacks blocks and followers had none. Reusing that state would make every
  subsequent result invalid.
- Risk: a resilient Bitcoin clock correctly keeps running, but an experiment
  controller that releases cadence before the system under test is assembled
  can manufacture irrecoverable boundary failures and misleading liveness
  findings.
- Required action: keep Bitcoin and its clock Stacks-blind. Render initial
  cadence policy as paused, allow Bitcoin to bootstrap idempotently to the
  regtest base, and let lifecycle policy release cadence only after all roles
  are live plus a bounded settling window. Always recreate clean PVCs after a
  failed bootstrap; never call later recovery evidence a baseline.

## F-008: Evidence collection did not fail closed on invalid arguments

- Classification: harness defect
- State: fixed
- Evidence: an accidentally reversed `EVIDENCE_DIR MANIFEST` invocation emitted
  repeated file and manifest errors, but the collector lacked strict shell mode
  and continued through later capture functions. In a larger workflow its exit
  status could therefore appear successful.
- Risk: a bundle can exist without the evidence it claims to contain—the same
  false-pass class this harness is intended to eliminate.
- Required action: the standalone collector now uses `set -euo pipefail` and
  retains explicit best-effort handling only for optional metrics/log sources.
  Campaign and soak drivers must also write explicit classification-error
  markers for intentionally non-blocking analysis steps.

## F-009: A loopback `data_url` cannot serve a remote legacy peer

- Classification: resolved extraction mismatch; incomplete initial diagnosis
- State: fixed with runtime container-IP substitution; independently required,
  but it was not the cause of the empty peer sets in the live run
- Evidence: `/v2/neighbors` on companion and follower showed the miner bootstrap
  peer at its Pod IP with `authenticated: true` during an early observation,
  yet both remained at Stacks height zero while the miner reached height four.
  The rendered current-main
  config still advertised `data_url = http://127.0.0.1:20443`, inherited from
  the libp2p environment where object transfer did not depend on the legacy
  peer's advertised HTTP endpoint. A later clean observation showed the primary
  connection failure was F-011; the loopback advertisement would still have
  prevented remote HTTP transfer once a peer attempted it.
- Risk: peer-count and authentication checks can look healthy while the data
  plane is unusable. A topology-only assertion would miss this completely.
- Required action: substitute the runtime container IPv4 into both P2P and
  data URLs, and retain the behavioral equal-height adoption assertion as the
  acceptance gate.

## F-011: Legacy P2P rejects Kubernetes Pod peers unless private neighbors are enabled

- Classification: resolved environment/config mismatch
- State: fixed and verified in a clean-volume stage-one run
- Evidence: follower and companion could reach the miner's RPC endpoint and
  resolved its bootstrap identity and Pod IP, but all three `/v2/neighbors`
  collections were empty. Current main defaults
  `connection_options.private_neighbors` to `false`; the config documentation
  states that this rejects incoming private-IP peers, avoids initiating to
  them, filters them from walks, and skips private peers for data transfer.
  All kind Pod addresses in this run were in `10.244.0.0/16`.
- Risk: a private-cluster harness can report healthy RPC/readiness while its
  actual Stacks data plane is completely disconnected. Peer identity and
  endpoint correctness do not override the private-address policy.
- Required action: render `private_neighbors = true` explicitly for private
  attacknet profiles, assert non-empty authenticated peer sets, and require
  cross-node Stacks-tip adoption—not merely common burn height—before accepting
  a capacity stage.

## F-012: Diagnostic probes require their own deadlines

- Classification: harness reliability finding
- State: identified; evidence collector hardening pending
- Evidence: an in-Pod connectivity probe without a portable client/deadline
  caused a parallel diagnostic batch to remain blocked until the outer tool was
  terminated. The actor image also lacks `nc`, so diagnostics cannot assume a
  full troubleshooting toolset inside production-like containers.
- Risk: one wedged or minimally provisioned actor can stall evidence capture
  and prevent the harness from recording the failure that caused the stall.
- Required action: give every probe a bounded outer deadline, record timeout or
  missing-tool outcomes explicitly, and prefer a dedicated diagnostic workload
  or language/runtime already guaranteed by the actor image.

## F-013: `/v2/neighbors` bootstrap authentication is not live-connectivity evidence

- Classification: observability/API semantic ambiguity
- State: identified; attacknet interpretation and behavioral gates corrected
- Evidence: the endpoint constructs `bootstrap` and `sample` rows from PeerDB
  candidates and reports `authenticated: true` without consulting a live
  conversation. Only `inbound` and `outbound` enumerate conversations and use
  their actual authentication state. This made an early failed run appear to
  have an authenticated bootstrap connection even while every live connection
  set and neighbor gauge was empty.
- Risk: topology UIs and health gates can draw or count configured candidates
  as working data-plane edges, producing a false connected-network result.
- Required action: use only authenticated inbound/outbound conversations (or
  live neighbor gauges) for connectivity. Show bootstrap/sample separately as
  configured or learned candidates, never as active edges.

## F-014: Equal-height-at-zero is not a useful post-bootstrap health invariant

- Classification: harness false-pass finding
- State: fixed in the shared verifier
- Evidence: an early snapshot at burn height 203 reported zero drift because
  every node was at Stacks height zero, even though no follower had yet adopted
  a Stacks block. The drift arithmetic was correct but incomplete as a stage
  acceptance condition.
- Risk: a wholly stalled or disconnected cohort can satisfy agreement-only
  gates.
- Required action: post-bootstrap verification now requires a configurable
  minimum observed Stacks height (default one) in addition to bounded burn and
  Stacks drift. Long-run gates must also require forward progress over time.

## F-010: Old ready replicas can make a new StatefulSet revision look Ready

- Classification: harness defect
- State: fixed; live rollout regression pending
- Evidence: immediately after the data URL changed, the CR reported `Ready 7/7`
  and lifecycle released burn cadence even though node Pods had not yet rolled.
  The operator counted only `status.readyReplicas`, which still described the
  prior StatefulSet revision.
- Risk: configuration/fault transitions can be declared complete while the
  system under test is still running old code or config. This contaminates
  start timestamps, stabilization windows, and post-fault recovery evidence.
- Required action: readiness now also requires StatefulSet generation to be
  observed, at least one updated replica, and equal non-empty current/update
  revisions. A regression test supplies an old ready replica during a pending
  generation and requires `Progressing`.

## F-030: Capacity preflight did not reserve space for the cold-run write burst

- Classification: harness/infrastructure reliability finding
- State: identified; admission-capacity guard pending
- Evidence: the first corrected full-topology launch exhausted Docker
  Desktop's shared VM disk while bitcoind was writing genesis state and Grafana
  was creating its SQLite database. Kubernetes had admitted the workloads and
  did not report node `DiskPressure`; the preflight sampled capacity before the
  cold-build and cold-start write burst rather than proving adequate headroom
  for it.
- Risk: a protocol run can fail for an apparatus resource limit and look like a
  node or consensus failure. A passing point-in-time capacity check is not a
  reservation and does not bound the subsequent write amplification.
- Required action: record Docker VM and Kubernetes ephemeral-storage headroom,
  set actor ephemeral-storage requests/limits where useful, and require a
  conservative free-space margin before a full launch. Classify ENOSPC as an
  infrastructure failure and capture it automatically.

## F-031: Cold IBD can queue stale observer events across signer initialization

- Classification: harness ordering defect exposing a transport-independent
  signer liveness defect
- State: baseline fix implemented; clean-cluster verification pending
- Evidence: all ten signers were declared Ready by an executable probe that
  only tested `/proc/1/status`. Their companion nodes performed rapid IBD while
  signer initialization was still failing. The signer event socket was already
  bound before the companion registered its observer, proving that TCP
  readiness alone is insufficient: the receiver accepted historical events
  into its in-process channel while the RPC-dependent runloop was
  uninitialized. A signer later initialized against companion burn height 216,
  then drained queued event heights beginning around 12; events at 142/143 and
  onward logged `fork detected` against the much newer state. No signer received
  a Nakamoto proposal and the network stalled after Stacks height 17.
- Risk: a test baseline can deterministically corrupt signer state before any
  fault is injected. The underlying condition—observer delivery substantially
  lagging the node's live RPC view—is also realistic after receiver outages or
  backpressure and should remain an explicit adversarial scenario.
- Required action: `stacks_signer_runloop_ready` distinguishes successful
  runloop initialization from process/TCP availability, but initialization is
  not participation. The corrected lifecycle advances by exact burn-height
  barriers: companion IBD with observers disabled, observer enablement before
  the reward-cycle transition, one block to calculate and observe the signer
  set, and an explicit current-cycle-registration gate before Nakamoto
  activation. The underlying delayed-event behavior is recorded separately as
  GH issue candidate 14. Add a deliberate stale-observer/backlog campaign and
  require it to produce a classified recovery or captured signer defect, never
  an unexplained stall.

## F-032: Incident capture accepted positional arguments but failed opaquely with flags

- Classification: evidence-tool usability finding
- State: fixed; regression invocation pending
- Evidence: an initial diagnostic invocation supplied named flags to the
  positional-only capture script. The command did not create the expected
  evidence tree and the mistake was discovered only by inspecting its output;
  a second positional invocation captured the complete incident.
- Risk: under time pressure, a syntactically plausible invocation can lose the
  highest-value evidence window while appearing to have run.
- Required action: the collector now supports exact positional or named forms,
  rejects unknown/missing arguments before collection, prints the resolved
  network/namespace/phase/destination, and retains its machine-readable
  completeness marker.

## F-033: Attacknet image builds sent multi-gigabyte non-build assets to Docker

- Classification: harness build-efficiency and disk-reliability finding
- State: fixed; next cold-build context size verification pending
- Evidence: a cold `contrib/attacknet/Dockerfile` build transferred a 2.15 GiB
  context even though `target/`, generated topology, and evidence were already
  ignored. More than 1.8 GiB came from non-workspace fuzz corpora under
  `stacks-signer-bridge/` and `stacks-network/`; the dashboard source tree and
  legacy Docker harness added further unrelated data.
- Risk: each rebuild writes needless data into Docker Desktop's shared VM,
  lengthens the feedback loop, and increases the likelihood of the ENOSPC
  infrastructure failure in F-001/F-030.
- Required action: `.dockerignore` now excludes the non-workspace fuzz,
  dashboard, and legacy Docker trees from this root-context build. Retain a
  build regression that verifies required Cargo workspace inputs remain
  present, and record context transfer size during future cold builds.

## F-034: Kubernetes Ready did not mean a signer could vote in the current cycle

- Classification: harness false-readiness finding and production observability
  gap
- State: metric and attacknet gate implemented; clean live verification pending
- Evidence: all signer Pods passed their readiness probes once the outer
  runloop initialized, but the retained run initialized them only after
  Nakamoto activation. Logs then reported `NoRegisteredSigners`; every signer
  received zero proposals and emitted zero votes. At the next reward-cycle
  boundary all nodes stalled with no canonical PoX anchor.
- Risk: a healthy process, HTTP endpoint, and initialized runloop can all be
  true while the signer contributes no weight. Orchestration and operator
  dashboards can report full availability during a network-wide participation
  failure.
- Required action: export bounded gauges for current- and next-cycle
  registration, require current-cycle registration in the signer readiness
  probe and lifecycle gate, and keep transport reachability separate through
  the signer's `runtimeExposure: reachable` service.

## F-035: Apparent cadence failure was confounded by a missing StackerDB subscription

- Classification: superseded diagnostic hypothesis; retained as an evidence
  calibration warning
- State: disproved as the cause of the current-main Kubernetes failure by F-043
- Evidence: at burn 233 miner-2 wrote proposal slot 2 version 1 at
  `06:49:36.378`. It overwrote that slot with version 2 about 39.5 seconds
  later. The first peer-side attempt associated with the newer slot appeared
  roughly another 39 seconds later, after the canonical `.miners` signer had
  changed, and was correctly rejected. The exact version-1 signature appears
  only in miner-2's local write log and no signer received a proposal. The
  20-second burn interval was shorter than observed dissemination, whereas
  Bitcoin mainnet cadence is much longer than the default inventory periods.
- Counter-evidence: after enabling the missing subscriptions, all ten
  companions exposed `.miners`; a fresh burn-230 proposal reached a signer in
  tens of milliseconds, validated in 13 ms, and was accepted. Two subsequent
  same-tenure blocks were also validated and accepted within seconds. This is
  incompatible with the claim that a 60-second interval caused the observed
  total delivery failure.
- Risk: time compression can still selectively accelerate one protocol plane,
  but using a tainted run to calibrate cadence can lead to unnecessary sleeps
  that hide the real configuration defect.
- Required action: measure proposal-to-receipt and proposal-to-threshold on a
  fresh corrected run. Keep faster cadence as a named stress dimension, but do
  not cite the pre-F-043 latency samples as a healthy StackerDB baseline.

## F-036: `burst N` continued mining after N blocks

- Classification: harness policy-control defect
- State: fixed and behaviorally verified on the retained tainted run
- Evidence: the policy helper wrote `MODE=run` with `BURST_BLOCKS=N`. Once the
  clock decremented the burst to zero, run mode allowed ordinary cadence to
  continue, so a caller could not create a stable protocol-height barrier. The
  corrected helper writes `MODE=pause`; a live `burst 1` advanced Bitcoin from
  height 362 to exactly 363 and remained paused at policy generation 5.
- Risk: configuration rolls and signer-set transitions can be crossed while
  the harness claims the burnchain is frozen, invalidating causality and replay.
- Required action: retain exact-height behavioral assertions for every phase
  transition and record each requested and observed height in the run ledger.

## F-037: Stale `.miners` chunks can masquerade as current key mismatches

- Classification: diagnostic ambiguity
- State: classified; bounded StackerDB outcome metrics pending
- Evidence: miners logged `Bad DB slot signer` for chunks fetched after a new
  sortition changed the two authorized `.miners` slot owners. Timestamp and
  signature correlation proved the warnings referred to earlier-tenure chunks,
  not the current proposal initially under investigation. Searching only by
  contract, slot, or consensus-view hash conflated several writes.
- Risk: incident responders can change correct miner keys or weaken
  authorization based on an unrelated stale-fetch warning.
- Required action: correlate contract, slot, version, signature hash, write
  time, fetch time, local sortition and disposition. Add bounded counters for
  accepted, stale-view, bad-signer and missing-slot StackerDB outcomes so the
  dashboard exposes the distribution without log archaeology.

## F-038: Attacknet lifecycle needs protocol-height phases, not startup sleeps

- Classification: orchestration design correction
- State: implemented; clean live verification pending
- Evidence: a two-second bootstrap cadence crossed reward-cycle and Nakamoto
  boundaries while companions rolled and signers initialized. Pod readiness
  ordering could narrow the race but could not prove which protocol state each
  actor held at activation.
- Risk: startup speed, image pull variance, PVC placement and node load change
  protocol outcomes, making an identical seed non-reproducible.
- Required action: the rendered manifest now carries bootstrap, observer,
  signer-registration and Nakamoto activation heights. Lifecycle advances with
  exact paused bursts, verifies node convergence at each barrier, and permits
  steady cadence only after every signer is a current-cycle participant.

## F-039: Raw actor logs are node-local and can disappear before forensics

- Classification: attacknet observability and evidence-retention gap
- State: identified; Loki/Alloy integration in progress
- Evidence: Prometheus centrally scrapes actor metrics and the authenticated
  event bridge persists orchestrator events, but raw stdout/stderr is read from
  containerd only when `kubectl logs` or incident capture runs. Only the current
  and immediately previous container are queried. Rotation, Pod eviction, or
  loss of a worker can therefore remove the causal log window.
- Risk: a long or destructive campaign may preserve the invariant failure but
  lose the cross-actor messages required to establish root cause. Grafana can
  show metrics without providing the corresponding log sequence.
- Required action: collect container logs centrally with bounded retention and
  collector-attached network, actor, role, Pod UID, node, container, run, and
  image identity. Treat message bodies as actor-self-reported and potentially
  malicious; Kubernetes metadata and authenticated orchestration events remain
  the authoritative correlation sources.

## F-040: Confirmed stacking requires a subsequent burn event before signer participation

- Classification: protocol-fixture sequencing fact exposed by a truthful gate
- State: corrected in the attacknet manifest; clean rerun pending
- Evidence: all ten `stack-stx` transactions were confirmed at burn height 220.
  At 221 every signer reported `runloop_ready=1` but
  `registered_for_current_reward_cycle=0`. An exact diagnostic block to 222
  caused all ten runloops to refresh from reward cycle 10 to 11 and report
  current-cycle registration before activation at 223.
- Risk: a harness that equates transaction confirmation or runloop readiness
  with participation crosses activation one event too early and creates a
  network with zero effective signer weight.
- Required action: use height 222 as the signer-registration barrier, retain
  the current-cycle gauge as the decisive assertion, and record requested and
  observed heights rather than inserting a timing sleep.

## F-041: A transient event-journal disconnect failed an otherwise healthy launch

- Classification: harness evidence-transport reliability defect
- State: fixed with bounded retry; clean rerun pending
- Evidence: the full network reached `Ready 31/31`, all signers registered, and
  the first post-activation snapshot later passed. While recording the baseline
  actor inventory, one loopback POST inside the event-journal Pod ended with
  `RemoteDisconnected`; `set -e` classified the entire lifecycle as failed.
- Risk: a momentary observability transport error can masquerade as protocol
  failure and prematurely seal an otherwise valid run descriptor.
- Required action: retry the identical authenticated, idempotent event up to
  three times. Persistent failure still preserves the admitted network and
  fails the evidence gate; transient failure no longer invalidates the run.

## F-042: Burn-block observer delivery can lead companion RPC visibility by one block

- Classification: transport-independent signer/node ordering finding; impact
  under investigation
- State: reproducible, with successful recovery demonstrated in the same
  occurrence; no participation loss observed
- Evidence: at burn heights 223, 224, and 225 the signer received the correct
  new-burn-block event, then its RPC check reported the companion at exactly the
  preceding height and failed local-state update with `Node has not processed
  the next burn block yet`. The companion converged shortly afterward and the
  full 18-node snapshot remained canonical.
- Risk: if the signer does not re-evaluate after companion convergence, every
  burn boundary can suppress state publication or proposal handling even
  though both components are individually healthy. The repeated StackerDB 404
  for signer-state publication may be downstream evidence, but causality is not
  yet established.
- Required action: correlate observer callback timing, companion chainstate
  commit, retry behavior, signer-state publication, and proposal/vote outcomes
  across several tenures. File a current-main issue only after distinguishing a
  harmless retried ordering window from persistent participation loss.
- Follow-up evidence: at burn 230 signer 1 logged the one-block RPC mismatch at
  `2301.131`, then evaluated the new proposal at `2303.215` with both global and
  local state at burn 230, validated it, voted Accepted, and observed 76% weight
  reach threshold. This occurrence recovered in about two seconds and did not
  suppress the vote. Retain the condition as a measurable recovery path rather
  than filing it as a liveness defect on this evidence alone.

## F-043: A signer companion silently omits proposal transport unless configured as a `stacker`

- Classification: current-main configuration ambiguity and attacknet bootstrap
  defect; transport-independent of libp2p
- State: topology fixed and live diagnostic verified; fresh lifecycle run
  pending
- Evidence: miners repeatedly accepted proposals into their local
  `ST000000000000000000002AMW42H.miners` slots, while every signer companion's
  metadata endpoint returned `StackerDB contract not found` and no signer log
  contained the proposal hashes. In current main, configuration finalization
  calls `add_miner_stackerdb()` and `add_signers_stackerdbs()` only when
  `[node].miner` or `[node].stacker` is true. A companion configured with both
  false can follow canonical burn and Stacks tips and appear healthy, but it
  never constructs the database that carries miner proposals.
- Risk: the overloaded `stacker` name looks like a consensus role instead of a
  transport subscription switch. A signer operator can pair a healthy signer
  with a healthy follower node and receive burn events while receiving zero
  block proposals, producing total participation loss with no direct startup
  error.
- Required action: render signer companion nodes with `miner = false` and
  `stacker = true`; retain a topology test for this exact distinction; and add
  a pre-activation behavioral assertion that the companion `.miners` metadata
  endpoint exists. Consider a clearer explicit `subscribe_signer_stackerdbs`
  configuration or startup diagnostic in the production node.
- Verification: after rolling only the corrected companion configuration with
  Bitcoin paused, all ten `.miners` metadata endpoints changed from 404 to 200.
  An exact one-block diagnostic then produced a proposal accepted by signers,
  followed by signed Nakamoto blocks at heights 19, 20, and 21. Proposal
  transport, independent companion validation, response transport, threshold
  aggregation, and Nakamoto block propagation all executed end to end.

## F-044: Docker Desktop exhausted shared node storage without Kubernetes DiskPressure

- Classification: local-cluster capacity and false-admission finding
- State: preflight fixed and live; host capacity restored
- Evidence: Loki, Alloy, and a replacement Grafana were scheduled but failed
  their first writes with `ENOSPC`. Kubelet summary reported exactly
  `availableBytes=0` and about 98.9 GB used for both node and image filesystems
  on all three nodes, while every Node condition still reported
  `DiskPressure=False`. Actor PVC data was only about 3--21 MiB per workload and
  the largest actor log was about 7 MiB, excluding the active network itself as
  the dominant consumer. Docker Desktop separately reported 8.5 GB of
  reclaimable build cache and 10.5 GB of reclaimable unused images; historical
  named volumes remain protected from cleanup.
- Risk: Kubernetes admits a complete experiment and reports healthy nodes even
  though evidence services cannot persist data. A protocol failure can then be
  accompanied by missing logs, a broken event journal, or Grafana migration
  errors, defeating root-cause analysis while the control plane still appears
  healthy.
- Remediation: lifecycle and capacity preflight now query kubelet
  `/stats/summary` before applying observability or actors, record both root and
  image filesystem availability per node, and fail below a conservative floor
  unless a negative-control scenario explicitly opts in. Docker Desktop's
  restart/upgrade restored roughly 51.3 GB available on each kind node; the
  clean stage-1 run subsequently admitted Loki, Alloy, Grafana, and every actor
  without storage errors. Historical evidence and actor volumes were not used
  as an unscoped cleanup target.

## F-045: Concurrent harness writers had no cluster-wide run ownership

- Classification: harness attribution and resource-governance defect
- State: fixed in entry points; fresh concurrent negative control pending
- Evidence: lifecycle, cadence, campaign, and ad-hoc diagnostic commands could
  mutate the same local cluster independently. Subagents were able to begin an
  observability rollout while a preserved protocol-diagnostic network was
  active, which made the resulting `ENOSPC` investigation initially ambiguous
  and allowed unrelated experiments to compete for the same finite node
  filesystem.
- Risk: an attacknet can attribute a failure to Stacks only if its own control
  actions are totally ordered. Concurrent applies, fault injection, cadence
  changes, or teardown can manufacture failures absent from the recorded
  scenario and make a reproduction seed insufficient.
- Required action: allow exactly one persistent network per cluster; serialize
  every mutating operation with a token-protected Kubernetes lease carrying
  owner, purpose, network, and acquisition time; permit concurrent read-only
  forensics; never auto-steal a stale lease; and record any explicit
  negative-control bypass. Lifecycle apply/delete, burnchain policy changes,
  and complete fault campaigns now enforce this contract.

## F-046: Teardown attempted to append to an already-finalized run ledger

- Classification: harness evidence-integrity/lifecycle defect
- State: fixed; exercised by teardown of the preserved diagnostic run pending
- Evidence: bootstrap failure correctly finalized its descriptor as `failed`,
  but later lifecycle deletion unconditionally appended a `run-final-status`
  assertion and finalized again. The run ledger intentionally rejects both
  operations after finalization, so evidence-preserving teardown would abort
  before deleting the admitted network.
- Risk: the more faithfully a failed run is sealed, the less likely its cleanup
  is to succeed, leaving resources and leases behind and encouraging unsafe
  manual deletion.
- Required action: treat finalization as immutable. Teardown may add the final
  assertion and seal a `running` descriptor; for an already-finalized run it
  must retain that status and export the existing ledger without rewriting it.

## F-047: Docker Desktop bundles a kubectl client outside supported server skew

- Classification: local attacknet tooling/version ambiguity
- State: fixed locally; preflight/version recording still to implement
- Evidence: the active Docker Desktop kind API server reports Kubernetes
  v1.36, while both `/usr/local/bin/kubectl` and Docker.app's bundled binary are
  v1.34.1. Commands warn that the two-minor difference exceeds Kubernetes'
  supported client/server skew. `helm` is not installed at all, despite the
  operator and planned Headlamp deployment being Helm-packaged.
- Risk: ordinary commands currently work, but schema, wait, and newer-resource
  behavior are not a defensible acceptance surface when the controlling client
  is outside supported skew. Hand-written install steps can also drift from the
  chart when Helm is silently absent.
- Remediation: Homebrew kubectl v1.36.3 now matches the v1.36.1 server within
  patch-level skew, and Helm v4.2.4 is installed. The older `/usr/local/bin`
  kubectl remains on disk but is later in `PATH`.
- Required action: pin a supported kubectl and Helm release for this
  cluster, record their versions in every run descriptor, and make preflight
  reject unsupported skew instead of merely retaining kubectl's warning.

## F-048: Offline CRD tests and Helm lint accepted schemas rejected by Kubernetes 1.36

- Classification: attacknet control-plane portability defect
- State: fixed and server-side dry-run verified
- Evidence: the initial `FaultCampaign`/`AttacknetRun` schemas passed their
  structural tests and `helm lint`, but the live v1.36 API rejected combinations
  of named properties with `additionalProperties: false`, quadratic
  `uniqueItems` constraints, an over-budget `oldSelf` CEL rule, and CEL access
  to the deliberately dual-shaped network/I/O `delay` field.
- Risk: a locally convincing API implementation would fail at installation on
  the exact target cluster. More subtly, relying only on client parsing and
  Helm lint would make CRD compatibility claims that were never exercised by
  an API server.
- Remediation: use Kubernetes pruning plus explicitly bounded arrays, retain
  the compiler/controller as action-dependent admission authority, remove the
  CEL rules that cannot type the dual-shaped field, and require server-side
  dry-run of every CRD and rendered chart in the release gate. Both new CRDs
  and all rendered controller/RBAC resources now pass that gate on v1.36.1.

## F-049: Same-Pod active probes are isolated but not cryptographically attributable

- Classification: forensic trust-boundary limitation
- State: bounded and documented; stronger attestation is optional future work
- Evidence: the controlled `attacknet-probe` sidecar has no service-account
  token, accepts only operator-generated enrolled peer/port requests, and owns
  the only intended listener on Pod port 18080. The run controller pins the
  exact Ready Pod UID/IP and requires the probe container to remain Ready.
  However, all containers in a Pod share one network namespace. A deliberately
  modified actor could attempt to occupy that port while the probe is absent or
  restarting, and the HTTP response is not signed by a probe-only key.
- Risk: ordinary actor logs or payloads cannot satisfy a fault assertion, and a
  persistent impersonator prevents the real probe from becoming Ready, but a
  narrow readiness-observation race is not cryptographically excluded. Calling
  these observations tamper-proof against the co-located actor would overstate
  their provenance.
- Required action: classify missing/unready/mismatched probe evidence as
  Inconclusive and retain the exact probe container state in incident evidence.
  If scenarios require protection from same-Pod response impersonation, add a
  per-Pod signing key mounted only in the probe and verify signatures in the run
  controller, or move the probe to a separate Pod while explicitly accepting
  the loss of same-network-namespace, clock, and filesystem fidelity.

## Pending additions

## F-050: Imperative image overrides can make Helm 4 upgrades and rollbacks conflict

- Classification: local attacknet control-plane ownership ambiguity
- State: recovered; runbook prevention pending
- Evidence: upgrading the existing `hacknet` release with Helm 4 server-side
  apply failed because an earlier `kubectl set image` manager owned
  `.spec.template.spec.containers[name="operator"].image`. Helm's attempted
  rollback then failed on the same field conflict. The running old operator
  remained available, but the release was left `failed` until the deliberate
  `--force-conflicts` upgrade returned ownership to Helm.
- Risk: a normal local debugging command can make both upgrade and automatic
  rollback fail, leaving the harness control plane at an ambiguous revision.
  An experiment started in that state cannot truthfully identify which
  controller implementation admitted it.
- Required action: change development images through Helm values plus a
  rollout annotation, not `kubectl set image`; make preflight reject a failed
  Helm release and record Pod image IDs. Treat `--force-conflicts` as an
  explicit ownership-recovery operation, not a routine upgrade flag.

## F-051: Helm does not add or upgrade CRDs for an existing release

- Classification: attacknet install/upgrade lifecycle gap
- State: fixed in the local installer and proven live
- Evidence: the release predated the `FaultCampaign` and `AttacknetRun` CRDs.
  Helm upgraded the Deployment resources but, by design, did not apply new
  files from the chart's `crds/` directory. The run controller started and
  repeatedly received API 404 for both resources, keeping `/readyz` at 503.
  Explicit server-side application of the two CRDs caused the already-running
  controller to recover and allowed Helm to complete without a restart.
- Risk: a chart can report a workload rollout while its API prerequisites are
  absent, and a user may misclassify the resulting 404 loop as an operator bug.
- Remediation: `install-local.sh` applies all three CRDs server-side before
  `helm upgrade`, waits for each API to become Established, and requires an
  explicit conflict-recovery flag before reclaiming schema ownership. The
  corrected installer was used for the accepted clean stage-1 run. Retain
  server-side dry-run as the compatibility gate; do not assume Helm owns CRD
  lifecycle after initial installation.

## F-052: Grafana actor discovery depended on a late synthetic metric

- Classification: human-observability truthfulness defect
- State: fixed live and regression-tested
- Evidence: Prometheus was successfully scraping the miner, signer,
  companion, and follower with collector-attached `attacknet_network`,
  `attacknet_actor`, and `attacknet_role` labels, while both Grafana dashboards
  populated their variables from `attacknet_actor_info{network,actor,role}`.
  That orchestrator metric is emitted only after an actor-state journal event;
  no such series existed during bootstrap, leaving Network empty and every
  actor query filtered to `No data`. Fault counters without actor filters still
  displayed zero, making the page look connected but the network absent.
- Risk: the primary human incident surface hid a healthy active network during
  precisely the bootstrap interval where operators need it most. A reader
  could mistake dashboard wiring failure for total actor or telemetry failure.
- Remediation: discover Network/Role/Actor directly from the live `up` target
  labels and retain `attacknet_actor_info` only for admitted image/placement
  metadata. The corrected dashboard was provisioned live and its four actor
  targets returned `up=1`.

## F-053: Fast bootstrap crossed the signer-set cutoff before stacking confirmed

- Classification: deterministic harness liveness and evidence defect
- State: fixed in phase model and proven by a fresh clean run
- Evidence: a fresh stage-1 run burst-mined from burn 202 to 220 while Stacks
  nodes were still processing the compressed epoch schedule. The stacker then
  submitted and confirmed its PoX-4 transactions at cycle 11's start, after
  the cycle's prepare/snapshot boundary. At burn 222 the signer correctly
  reported `runloop_ready=1` but both current- and next-cycle registration as
  zero. Lifecycle paused Bitcoin and waited 900 seconds for current-cycle
  registration, a condition that could only change after later burn blocks,
  producing a deterministic deadlock. The sealed bootstrap-failure bundle is
  retained under the generated stage-1 run directory.
- Risk: the harness could manufacture a signer outage while claiming to prove
  a pre-Nakamoto participation barrier. Faster machines or different API
  timing merely changed whether the race appeared, so earlier passes were not
  portable evidence.
- Remediation: expose structured stacker submission state; pause at PoX-4
  enrollment (burn 208); advance one burn block at a time; and prove every
  configured signer address has non-zero canonical `locked` state before the
  cycle-11 prepare cutoff at burn 215. Crossing the cutoff without that proof
  is now impossible. Only after this gate may the lifecycle enable observers,
  require current-cycle signer readiness at 222, and enter Nakamoto at 223.
  The clean run retained at
  `contrib/attacknet/evidence/stage1-clean-current-main-20260815/` confirmed
  canonical lock at burn 212, before the cutoff, and first-start signer
  registration without a restart.

## F-054: A compound Bash `local` assignment aborted the enrollment barrier

- Classification: attacknet harness reliability defect
- State: fixed and regression-tested
- Evidence: the first corrected enrollment run stopped at burn 208 with
  `seconds: unbound variable`. `wait_stacker_submission_window` declared
  `seconds="$1"` and computed its deadline in the same `local` command; Bash
  expands the arithmetic expression before the new local value exists, and
  `set -u` turned that ordering detail into a fatal error. The complete sealed
  incident is retained at
  `contrib/attacknet/evidence/stage1-enrollment-shell-abort-20260815/`.
- Risk: a valid paused network could be abandoned by the harness before a
  protocol assertion ran, making infrastructure failure look like a signer or
  stacker failure.
- Remediation: split declaration, assignment, and deadline computation into
  separate commands and retain behavioral registration-lifecycle tests.

## F-055: Reapplying a rendered burn policy reused an acknowledged generation

- Classification: deterministic cadence-control defect
- State: fixed and regression-tested
- Evidence: resuming lifecycle against an admitted generation-2 burn policy
  reapplied the generated generation-1 ConfigMap. The controller incremented
  it to generation 2, while the clock correctly ignored that already-applied
  command ID; lifecycle then mistook the old generation-2 acknowledgement for
  its new request. No requested block was mined.
- Risk: a resume could silently skip a cadence instruction or satisfy an
  exact-height gate with a stale acknowledgement. That breaks both protocol
  sequencing and replay truthfulness.
- Remediation: `ensure_burnchain_policy` now creates the initial policy only
  when absent and otherwise preserves the admitted monotonic generation. The
  run ledger remains the authority for whether a recovery command was already
  requested.

## F-056: A cached `NotRegistered` signer entry suppresses reward-set retries

- Classification: transport-independent signer liveness defect in current main
- State: confirmed with sealed runtime evidence; upstream fix required
- Evidence: after canonical stacking was confirmed before the configured
  cutoff, the companion's `/v3/stacker_set/11` returned the signer's exact
  public key and weight. The signer simultaneously reported reward cycle 11,
  `runloop_ready=1`, and both registration gauges as zero. In
  `stacks-signer/src/runloop.rs`, an early negative lookup installs
  `ConfiguredSigner::NotRegistered`; `is_configured_for_cycle()` then returns
  true for that placeholder, so later burn events never call
  `refresh_signer_config()` for the same cycle. Restarting only the signer,
  without mining a block or changing its companion, immediately produced
  `registered_for_current_reward_cycle=1`. The complete pre-recovery evidence
  is retained at
  `contrib/attacknet/evidence/stage1-notregistered-cache-20260815/`.
- Risk: a signer that queries just before its canonical reward-set entry is
  available can remain unable to vote for the entire reward cycle unless an
  operator restarts it. Correlated startup or node-lag timing can therefore
  remove meaningful signing weight despite healthy RPC and chainstate later.
- Required action: distinguish a definitive absence from a reward set that is
  not available yet, and retry negative/unavailable configurations on later
  burn events with bounded backoff. Add a regression that first returns no
  entry, later exposes the signer in the same cycle, and proves registration
  without process restart. The deterministic attacknet baseline starts signers
  only after the canonical reward set is frozen; a separate early-start
  negative control must retain this as failed current-main behavior.

## F-057: Burn and Stacks heights shared an unusable dashboard scale

- Classification: human-observability presentation defect
- State: fixed live and regression-tested
- Evidence: the overview overlaid burn height (222) and Stacks tip height (15)
  in one chart. In a Nakamoto network, Stacks height advances at a substantially
  different cadence from the Bitcoin burnchain; either series can become
  visually flat or dominate the Y-axis as the run grows.
- Risk: an operator can miss cohort divergence or stalled Stacks progress even
  while the underlying series are present and accurate.
- Remediation: split the panel into independently scaled `Burn-chain cohort
  progress` and `Stacks-chain cohort progress` charts, while retaining the
  top-level spread statistics. The change passed all observability tests and
  was rolled into the active Grafana deployment.

## F-058: A rollout annotation did not prevent kind from running stale `:dev` code

- Classification: local image provenance and admission defect
- State: fixed and proven live
- Evidence: the rebuilt operator image contained per-actor suspension, and the
  StacksNetwork API admitted `signer-1.suspended=true`, but the resulting
  StatefulSet still had `replicas=1`. The Deployment's build annotation had
  forced a new Pod, while `imagePullPolicy: IfNotPresent` reused the worker's
  older cached `stacks-hacknet-operator:dev`. Inspecting `/app/controller.py`
  inside that Pod showed the old replica expression. This also omitted the
  burnchain runtime-policy mount, so the clock ran its default 20-second cadence
  and could not acknowledge the lifecycle's generation-2 policy. The failed
  pre-mining run was automatically sealed and exported before teardown.
- Risk: a run could record the new source digest and a fresh Pod UID while
  executing old controller code, invalidating every admission, orchestration,
  and replay claim downstream. A rollout annotation proves restart, not image
  identity.
- Remediation: `install-local.sh` now retags each local image with a tag derived
  from its full immutable Docker image ID, passes that content-specific tag to
  Helm, and retains the full ID as a Pod annotation. The admitted operator and
  run-controller `imageID` values now exactly match the local build IDs, and
  live inspection confirms the expected controller source. The installer also
  gained a read-only `--help`; previously, asking for help executed an install.

## F-059: Bootstrap readiness assumed every declared actor had a Pod

- Classification: phase-assertion model defect
- State: fixed and regression-tested
- Evidence: after per-actor suspension worked, Kubernetes correctly admitted
  seven actor StatefulSets, kept the signer at `replicas=0`, and created six
  actor Pods. The foundation gate compared Pod count directly with the seven
  workloads in the manifest, so it could never pass even though every active
  foundation actor was Ready.
- Risk: intentional suspension, staged upgrades, and future scale-to-zero fault
  scenarios would all look like unexplained bootstrap failure. Relaxing the
  count entirely would be worse because a genuinely missing StatefulSet or Pod
  could then pass unnoticed.
- Remediation: require the complete declared StatefulSet count first, derive
  the expected active Pod count from each admitted StatefulSet's nonzero
  replica intent, and independently require the named foundation actors Ready.
  Behavioral coverage proves a seven-actor topology with one suspended signer
  accepts exactly six active Pods and still rejects missing admitted resources.

## F-060: Network-scoped readiness inventory counted observability workloads as actors

- Classification: assertion-scope and resource-label ambiguity
- State: fixed and regression-tested
- Evidence: the replica-aware gate correctly queried StatefulSets, but selected
  only `testing.stacks.org/network`. Loki deliberately shares that network label,
  producing eight StatefulSets for a seven-actor topology and another impossible
  equality. Actor Pod inventory already required the additional
  `testing.stacks.org/actor` label.
- Risk: attaching any new network-scoped StatefulSet—logs, tracing, a proxy, or
  an adversarial helper—could break protocol bootstrap despite every actor being
  healthy. Conversely, treating all network-labelled workloads as actors would
  corrupt capacity and attribution metrics.
- Remediation: actor readiness inventory now requires both the network and actor
  labels for Pods and StatefulSets. The behavioral fixture includes an eighth
  observability StatefulSet and proves it cannot affect the seven-actor gate.

## F-061: Two lifecycle branches issued duplicate steady-state cadence commands

- Classification: mutually-exclusive phase-control defect
- State: fixed and regression-tested
- Evidence: the phased bootstrap reached burn 222, proved the signer registered,
  proved the companion subscribed to `.miners`, switched the clock to the
  requested 60-second steady cadence, and reached `Ready 7/7`. Because stage 1
  had no activation-gated miner, the later generic ungated-startup branch also
  ran and issued the same policy as a new generation. The clock was correctly
  sleeping for generation 9's 60-second interval and did not acknowledge
  generation 10 inside the command deadline, so lifecycle marked an otherwise
  healthy launch failed.
- Risk: successful protocol bootstrap could be reported as infrastructure
  failure, and an unnecessary second cadence command could perturb replay
  ordering or mine a block at an unintended boundary.
- Remediation: the generic post-Ready clock start is now restricted to
  single-phase topologies with no bootstrap resource and no activation-gated
  actors. A behavioral decision-table test proves two-phase, gated, and simple
  startup paths are mutually exclusive.

## C-001: Fresh staged current-main bootstrap reached Nakamoto consensus

- Classification: clean acceptance evidence
- Observation window: empty PVCs from burn 202 through Nakamoto burn 223/224
- Evidence: `contrib/attacknet/evidence/stage1-clean-current-main-20260815/`
  captures the admitted generation-2 network at `Ready 7/7`, exact local image
  IDs, Kubernetes state, trusted timeline, and run descriptor. Canonical signer
  funds locked at burn 212 before cutoff 215; the observer-enabled final
  generation reconciled with seven active Pods before mining continued; the
  signer initialized registered for reward cycle 11 on its first process start;
  and its companion subscribed to the legacy `.miners` StackerDB.
- Protocol result: at burn 223 the miner produced Nakamoto blocks, the signer
  received/validated/accepted four proposals with zero rejections, and miner,
  companion, and follower converged on the same burn height, Stacks height, and
  canonical tip. No actor container restarted during the accepted run.
- Boundary: this proves the corrected one-miner/one-signer/one-follower staged
  lifecycle and human observability surface. It is not the full 28-actor
  capacity baseline, a fault campaign, or the required 300+ burn-block soak.

Each capacity stage, negative control, fault campaign, mixed-version run, and
long soak must append findings here before its evidence is summarized. A clean
run is also evidence and should record the invariant and observation window.
