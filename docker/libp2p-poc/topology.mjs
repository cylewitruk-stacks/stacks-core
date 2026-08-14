#!/usr/bin/env node

import {createECDH, createHash} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const LIMITS = Object.freeze({signers: 10, miners: 3, followers: 5});
// PoC topology targets, not public-network recommendations. A signer needs
// room for every private rendezvous peer, a normal GossipSub mesh, and transient
// simultaneous-dial duplicates, but must not form an all-actor clique.
const CONNECTION_LIMITS = Object.freeze({actor: 12, signer: 16, miner: 32, bootstrap: 64});
// The accelerated burnchain can produce a flash block every five seconds.
// Keep a freshly restarted miner's replacement-commit delay below that floor;
// otherwise each burn arrival resets the timer and every miner can fall below
// Nakamoto's ordinary 3-of-6 commitment-frequency requirement.
const POC_BLOCK_COMMIT_DELAY_MS = 1_000;
const BOOTSTRAP_PEER_ID = '16Uiu2HAmU1MbqEPd87m36aZWn6qKUtPumc2SthnzhF4h2RXz4wTS';
const CONTRACT_ACCOUNT = 'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H';
const SIGNER_GENESIS_BALANCE_USTX = 10000000000000000n;

const NODE_IDENTITIES = Object.freeze({
  miners: [
    ['11', '16Uiu2HAmU1MbqEPd87m36aZWn6qKUtPumc2SthnzhF4h2RXz4wTS'],
    ['12', '16Uiu2HAmUMaeT2ucVsRqTNq7SprvajZ3CiBVW9bLZcdJ1zJFX9pm'],
    ['13', '16Uiu2HAmBS6hj6SfsNdkCWMngwfkUyxZGNNEQUGMDdoVDUvvpWBg'],
  ],
  signerNodes: [
    ['21', '16Uiu2HAkxh98QxUjCcFzVXtyDvcWZGZmBSgPS3S6Wn4XiuHzam3y'],
    ['22', '16Uiu2HAmLWNbjdkuVzmPCJxHbar4QJH39oNMm2ZWsuXXdD5Z88rD'],
    ['23', '16Uiu2HAkv1aJNiZHbaLFDzx3Xc4tVQKjznHbuq8YXi1bfhqQRNDY'],
    ['24', '16Uiu2HAm7mBKSw7i3Es7NtBB9gMcFgRh7VYENXX2zc4qbPj88CtW'],
    ['25', '16Uiu2HAm2cLES9ghDrRtNyLpCv7Q4nAdBws3R4QkDoRKKWHatDaT'],
    ['26', '16Uiu2HAkw2ENzpiuRXRgp5PEi4QjNL9MXQDbTBF2ECp2ADmM8WQL'],
    ['27', '16Uiu2HAmN1bWFdK6JSH9VAT62iBrgxWxJDZBvdWe7Ln2nTc76AfX'],
    ['28', '16Uiu2HAmGrMfwCctBx3Bma2sVMxNd7SbRduThRBcc1K1P49xDD6W'],
    ['29', '16Uiu2HAmDkZD9d2RXMXd2Sm1ZqfrzMk2VaJsb3tAr4tpeGPGbo7w'],
    ['2a', '16Uiu2HAkudGZ8H2ukZ34rpAcDy3wMRoz9jS6RTfBdetMGarDkVkz'],
  ],
  followers: [
    ['31', '16Uiu2HAmFv2v8JmBmsa3isoKoQBAE1LLKTmVVDwAZ453MwzRAn9d'],
    ['32', '16Uiu2HAm3sP2Sewmyi3orqUXRi24FM9zgEPSwDGBaRbwqoWygM6y'],
    ['33', '16Uiu2HAmE5Y8LT7FuEzm2oAbLhYXBU1WsgfobJVjvWcbaFRnUB7k'],
    ['34', '16Uiu2HAm6DMUAzPsRoNb6PyguXEVhswm2Qf47vYR3mkxeEHHMbTK'],
    ['35', '16Uiu2HAmE6awpL24qHiMygbqNPuq38bmJ7SFga8BCay5cpRLmPpZ'],
  ],
});

function signerPublicKey(privateKey) {
  const scalar = privateKey.endsWith('01') ? privateKey.slice(0, -2) : privateKey;
  const key = createECDH('secp256k1');
  key.setPrivateKey(Buffer.from(scalar, 'hex'));
  return key.getPublicKey('hex', 'compressed');
}

// Public keys are derived from the configured private scalars instead of
// being duplicated literals. The observer enrollment and the signer process
// therefore cannot silently disagree about public signer identity.
const SIGNERS = Object.freeze([
  ['41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc01', 'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H'],
  ['9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee01', 'ST2XAK68AR2TKBQBFNYSK9KN2AY9CVA91A7CSK63Z'],
  ['3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb7401', 'ST1J9R0VMA5GQTW65QVHW1KVSKD7MCGT27X37A551'],
  ['444444444444444444444444444444444444444444444444444444444444444401', 'ST361P1W3HRW7VTPD1S935RF8PJFMRAF4GJMPMQZN'],
  ['454545454545454545454545454545454545454545454545454545454545454501', 'ST1GY0T7R417K2Q2S17DJE3SVEMKRQ2EPJ4PGD5B8'],
  ['464646464646464646464646464646464646464646464646464646464646464601', 'ST2YS424BPZM2TR8TKEAFQDTA1441AAVR9ZP7K4S0'],
  ['474747474747474747474747474747474747474747474747474747474747474701', 'ST332XG8HFYG31EBQ2RWZ3R85AQ6VXTGXQHJYH0K5'],
  ['484848484848484848484848484848484848484848484848484848484848484801', 'ST2N5TCTPRMT6EXTFSCPTGBQ0K04B44H79XPH6YXS'],
  ['494949494949494949494949494949494949494949494949494949494949494901', 'ST64T36C5EABZ2T1Y6KWN03RSWAKJK59QHE2D83N'],
  ['4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a01', 'ST350FBN4H0EKWQCW6BTFK97RGXFS5QJ78E9NST20'],
].map(([privateKey, address]) => Object.freeze([
  privateKey,
  signerPublicKey(privateKey),
  address,
])));

// Derived by stacks-network/examples/poc_peer_ids.rs from the same signer
// secrets above. The authenticated observer can therefore join transport
// identities without collecting endpoints or trusting actor-supplied names.
const SIGNER_TRANSPORT_PEER_IDS = Object.freeze([
  '16Uiu2HAm7K2fEAn5W93hqHt3qhjMKTdDCDDPfyykqEcrgNNBAoqn',
  '16Uiu2HAmMLamjqzsFJ9GccubwzfbPtQPKZVeBD4ps8mwcqdnNy7L',
  '16Uiu2HAmGNLTSojuFPEghScUdmmzvdCJj4pytT8PauvEV2oUYvXG',
  '16Uiu2HAmHUkBjhghRE7eR4rz7JCefLf2hZoKXPhNhsDE9gekpWeX',
  '16Uiu2HAmGvqssCuScuZzmxCEfucqMekfW7tmDfTd5FTe3jdmqQr9',
  '16Uiu2HAm4i1xKgrgCUXM7VxL2y8i9ZXeH44G6eG3DxPr2W7foHJh',
  '16Uiu2HAmUEJVvfaTgnEmmbJurGYhm99ZLuufXHzKJezVZB6VxDq1',
  '16Uiu2HAmQGRQ5PwgeqoJEcLsQxsAtVEWAw8ccJ4sfcMjJWdma3DR',
  '16Uiu2HAmUmpyLndFZTjvqkZmwDz1jm3jjXPEEUHFam2M72dXRRax',
  '16Uiu2HAmA6krghbK1jJXGybCdPC87ghvE2iZ2iC2ey9LQkJ4TZg3',
]);

const MINER_KEYS = Object.freeze([
  ['11', '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1', 'n2PEoV6Abxnrpzoqqq1TJT5kw8G2dMPpBd', '19ec1c3e31d139c989a23a27eac60d1abfad5277d3ae9604242514c738258efa01'],
  ['12', '046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7eb1c2784a65901538479361e94c0a2597973adef0836a6a7eddf50b7997c88a3', 'n3BxbFxkvGbF9ANka8TXuihwKZBd9xaJVg', '616161616161616161616161616161616161616161616161616161616161616101'],
  ['13', '041d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599b6d846ca00fd42d38558d26a5ec4b91ae19bd68c5ab01497e0b57f52a2e0d5ef', 'mnZXRioUVq35tsCRk1DSoYUhwWaTGSz7a8', '626262626262626262626262626262626262626262626262626262626262626201'],
]);

function repeated(byte) {
  return byte.repeat(32);
}

function numberOption(name, fallback, max) {
  const marker = `--${name}=`;
  const raw = process.argv.find(arg => arg.startsWith(marker))?.slice(marker.length)
    ?? process.env[`POC_${name.toUpperCase()}`]
    ?? String(fallback);
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new Error(`${name} must be within [1, ${max}], received ${raw}`);
  }
  return value;
}

export function actorToken(id) {
  return `poc-${id}-token-${createHash('sha256').update(`stacks-libp2p-poc:${id}`).digest('hex').slice(0, 24)}`;
}

function epochsAndBalances(signers) {
  const epochs = [
    ['1.0', 0], ['2.0', 0], ['2.05', 203], ['2.1', 204], ['2.2', 206],
    ['2.3', 207], ['2.4', 208], ['2.5', 209], ['3.0', 223], ['3.1', 224],
    ['3.2', 225], ['3.3', 226], ['3.4', 227], ['4.0', 245],
  ].map(([name, height]) => `[[burnchain.epochs]]\nepoch_name = "${name}"\nstart_height = ${height}`).join('\n');
  const balances = signers.map(([, , address]) =>
    `[[ustx_balance]]\naddress = "${address}"\namount = ${SIGNER_GENESIS_BALANCE_USTX}`).join('\n');
  return `${epochs}\n\n${balances}`;
}

function connectionLimits(total) {
  return `max_established_incoming = ${total}
max_established_outgoing = ${total}
max_established_total = ${total}
peer_store_startup_dials = ${Math.min(8, total)}
# All PoC actors share a Docker IPv4 /24. Match the prefix ceiling to the
# actor ceiling so subnet diversity protection is not a hidden stricter cap.
max_connections_per_prefix = ${total}`;
}

function nodeConfig({
  name,
  identity,
  peerId,
  miner,
  mining,
  signers,
  connectionLimit,
  signerEventEndpoint,
}) {
  const bootstrap = name === 'miner-1' ? '' :
    `bootstrap_peers = ["/dns4/miner-1/tcp/20445/p2p/${BOOTSTRAP_PEER_ID}"]`;
  const minerConfig = miner ? `
[miner]
first_attempt_time_ms = 1000
subsequent_attempt_time_ms = 2000
block_commit_delay_ms = ${POC_BLOCK_COMMIT_DELAY_MS}
mining_key = "${mining[3]}"
block_reward_recipient = "STQM73RQC4EX0A07KWG1J5ECZJYBZS4SJ4ERC6WN"
activated_vrf_key_path = "/data/node/activated-vrf-key.json"
` : '';
  const wallet = miner ? `\nwallet_name = "libp2p-poc-${name}"\nlocal_mining_public_key = "${mining[1]}"` : '';
  const signerEventObserver = signerEventEndpoint ? `
[[events_observer]]
endpoint = "${signerEventEndpoint}"
events_keys = ["stackerdb", "block_proposal", "burn_blocks"]
` : '';
  return `[node]
name = "libp2p-regtest-${name}"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
data_url = "http://127.0.0.1:20443"
p2p_address = "127.0.0.1:20444"
prometheus_bind = "0.0.0.0:20446"
working_dir = "/data/node"
seed = "${repeated(identity[0])}"
local_peer_seed = "${repeated(identity[0])}"
miner = ${miner}
stacker = ${miner}
use_test_genesis_chainstate = true
pox_5_sbtc_contract = "${CONTRACT_ACCOUNT}.sbtc-token"
pox_5_sbtc_registry_contract = "${CONTRACT_ACCOUNT}.sbtc-registry"
pox_sync_sample_secs = 0
wait_time_for_blocks = 0
wait_time_for_microblocks = 0
mine_microblocks = false

[node.libp2p]
rollout_mode = "libp2p-only"
kademlia_server = ${miner}
bind = ["/ip4/0.0.0.0/tcp/20445"]
advertise = ["/dns4/${name}/tcp/20445/p2p/${peerId}"]
${bootstrap}
direct_block_push = true
direct_push_fanout = 3

[node.libp2p.limits]
${connectionLimits(connectionLimit)}

[node.libp2p.signer_bridge]
mode = "off"
${minerConfig}
[connection_options]
disable_block_download = true
disable_inbound_handshakes = true
disable_inbound_walks = true
public_ip_address = "127.0.0.1:20444"
auth_token = "12345"
${signerEventObserver}

[burnchain]
chain = "bitcoin"
mode = "nakamoto-neon"
poll_time_secs = 1
magic_bytes = "T3"
pox_prepare_length = 5
pox_reward_length = 20
burn_fee_cap = 20000
peer_host = "bitcoin"
peer_port = 18444
rpc_port = 18443
rpc_ssl = false
username = "devnet"
password = "devnet"
timeout = 30${wallet}
allow_stale_bitcoin_tip = true

${epochsAndBalances(signers)}
`;
}

function signerConfig(index, signer, minerIdentities) {
  const rendezvousPeers = minerIdentities
    .map(
      (identity, minerIndex) =>
        `"/dns4/miner-${minerIndex + 1}/tcp/20445/p2p/${identity[1]}"`,
    )
    .join(', ');
  return `stacks_private_key = "${signer[0]}"
node_host = "signer-node-${index}:20443"
endpoint = "0.0.0.0:30000"
network = "testnet"
auth_password = "12345"
db_path = "/data/signer.sqlite"
metrics_endpoint = "0.0.0.0:31000"
event_timeout_ms = 250
# PoC-only bounded fault-injection horizon. Production retains its longer
# default; this lets a companion outage prove abstention and recovery without
# holding the accelerated regtest tenure open for two minutes.
block_proposal_validation_timeout_ms = 15000

[libp2p]
rollout_mode = "libp2p-only"
bind = ["/ip4/0.0.0.0/tcp/30445"]
advertise = ["/dns4/signer-${index}/tcp/30445"]
bootstrap_peers = ["/dns4/miner-1/tcp/20445/p2p/${BOOTSTRAP_PEER_ID}"]
# These are dial/reconnect and role-directory rendezvous hints only. Miner-lane
# authority comes from canonical sortition-bound Role::Miner records.
rendezvous_peers = [${rendezvousPeers}]

[libp2p.limits]
${connectionLimits(CONNECTION_LIMITS.signer)}

[libp2p.signer_bridge]
mode = "off"
`;
}

function yamlService(name, lines) {
  return `  ${name}:\n${lines.map(line => `    ${line}`).join('\n')}\n`;
}

function nodeService(name, config, volume, {primary = false, delayedMiner = false, dependOnMiner = true} = {}) {
  const lines = [
    ...(primary ? ['build:', '  context: ../..', '  dockerfile: docker/libp2p-poc/Dockerfile'] : []),
    'image: stacks-core-libp2p-poc:local',
    'restart: unless-stopped',
    'depends_on:',
    '  bitcoin:',
    '    condition: service_healthy',
    ...(dependOnMiner ? ['  bitcoin-miner:', '    condition: service_healthy'] : []),
    ...(primary ? [] : ['  miner-1:', '    condition: service_healthy']),
    'environment:',
    '  RUST_LOG: "info,stacks_network=info"',
    ...(delayedMiner ? ['  NAKAMOTO_SOURCE_HOST: miner-1', '  NAKAMOTO_ACTIVATION_HEIGHT: "223"'] : []),
    ...(primary ? ['ports:', '  - "127.0.0.1:20443:20443"', '  - "127.0.0.1:20445:20445"', '  - "127.0.0.1:20446:20446"'] : []),
    'volumes:',
    `  - ./${config}:/config.toml:ro`,
    `  - ${volume}:/data`,
    ...(delayedMiner ? ['  - ./join-after-nakamoto.sh:/join-after-nakamoto.sh:ro'] : []),
    'healthcheck:',
    '  test: ["CMD-SHELL", "curl --fail --silent http://127.0.0.1:20443/v2/info >/dev/null"]',
    '  start_period: 20s',
    '  interval: 5s',
    '  timeout: 2s',
    '  retries: 90',
    ...(delayedMiner
      ? ['command: ["/bin/bash", "/join-after-nakamoto.sh"]']
      : ['command: ["stacks-node", "start", "--config", "/config.toml"]']),
  ];
  return yamlService(name, lines);
}

function signerService(index) {
  return yamlService(`signer-${index}`, [
    'image: stacks-core-libp2p-poc:local',
    'restart: unless-stopped',
    'depends_on:',
    `  signer-node-${index}:`,
    // The companion durably retries signer events. Starting the signer only
    // after companion health creates a cycle: the companion cannot complete
    // its first event delivery until the signer exists. The signer node client
    // already retries while the companion finishes booting.
    '    condition: service_started',
    'environment:',
    '  RUST_LOG: "info,stacks_network=info"',
    'volumes:',
    `  - ./generated/configs/signer-${index}.toml:/config.toml:ro`,
    `  - signer-${index}-data:/data`,
    'healthcheck:',
    '  test: ["CMD-SHELL", "test -r /proc/1/status"]',
    '  interval: 5s',
    '  timeout: 2s',
    '  retries: 30',
    'command: ["stacks-signer", "run", "--config", "/config.toml"]',
  ]);
}

function telemetryService(actor, port) {
  return yamlService(`telemetry-${actor.service}`, [
    'image: ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0',
    'restart: unless-stopped',
    'depends_on:',
    `  ${actor.service}:`,
    '    condition: service_healthy',
    '  telemetry-collector:',
    '    condition: service_started',
    'volumes:',
    '  - ../../contrib/stacks-network-observer/federation/agent.yaml:/etc/otelcol-contrib/config.yaml:ro',
    'command: ["--config=/etc/otelcol-contrib/config.yaml"]',
    'environment:',
    `  STACKS_METRICS_TARGET: "${actor.service}:${actor.type === 'signer' ? 31000 : 20446}"`,
    `  STACKS_FEDERATION_ENDPOINT: "http://telemetry-collector:${port}"`,
    `  STACKS_FEDERATION_TOKEN: "${actorToken(actor.id)}"`,
    'read_only: true',
    'tmpfs:',
    '  - /tmp:size=8m,noexec,nosuid',
    'security_opt:',
    '  - no-new-privileges:true',
    'cap_drop:',
    '  - ALL',
  ]);
}

function collectorConfig(actors) {
  const schema = JSON.parse(readFileSync(resolve(ROOT, '../../contrib/stacks-network-observer/federation/schema.json'), 'utf8'));
  const metricRegex = schema.metricNames.join('|');
  const metricLabelKeys = JSON.stringify(schema.metricLabelKeys);
  const extensions = actors.map(actor => `  bearertokenauth/${actor.id}:\n    scheme: Bearer\n    token: ${actorToken(actor.id)}`).join('\n');
  const receivers = actors.map((actor, index) => `  otlp/${actor.id}:\n    protocols:\n      http:\n        endpoint: 0.0.0.0:${4318 + index}\n        auth:\n          authenticator: bearertokenauth/${actor.id}`).join('\n');
  const resources = actors.map(actor => `  resource/${actor.id}:\n    attributes:\n      - {key: service.name, action: upsert, value: ${actor.type === 'signer' ? 'stacks-signer' : 'stacks-node'}}\n      - {key: stacks.federation.actor_id, action: upsert, value: ${actor.id}}\n      - {key: stacks.actor.type, action: upsert, value: ${actor.type}}\n      - {key: stacks.actor.role, action: upsert, value: ${actor.role}}\n      - {key: stacks.chain.id, action: upsert, value: "2147483648"}\n      - {key: stacks.network.id, action: upsert, value: regtest}\n      - {key: stacks.region, action: upsert, value: local}\n      - {key: stacks.telemetry.schema.version, action: upsert, value: "1"}`).join('\n');
  const pipelines = actors.map(actor => `    metrics/${actor.id}:\n      receivers: [otlp/${actor.id}]\n      processors: [memory_limiter, filter/schema, transform/privacy, resource/${actor.id}, batch]\n      exporters: [prometheus]`).join('\n');
  return `extensions:\n${extensions}\n\nreceivers:\n${receivers}\n\nprocessors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128
  filter/schema:
    error_mode: propagate
    metrics:
      metric:
        - 'not IsMatch(name, "^(${metricRegex})$")'
      datapoint:
        - 'attributes["signer_public_key"] != nil and not IsMatch(attributes["signer_public_key"], "^(02|03)[0-9a-f]{64}$")'
        - 'attributes["peer_id"] != nil and not IsMatch(attributes["peer_id"], "^[1-9A-HJ-NP-Za-km-z]{32,128}$")'
        - 'attributes["decision"] != nil and not IsMatch(attributes["decision"], "^(approved|rejected|unavailable)$")'
        - 'attributes["status"] != nil and not IsMatch(attributes["status"], "^(collecting|approved|rejected|timed-out)$")'
        - 'attributes["state"] != nil and not IsMatch(attributes["state"], "^(uninitialized|pending|initialized|unknown|no_valid_miner|active_miner)$")'
        - 'attributes["response_type"] != nil and not IsMatch(attributes["response_type"], "^(accepted|rejected|abstained)$")'
        - 'attributes["outcome"] != nil and not IsMatch(attributes["outcome"], "^(accepted|rejected)$")'
        - 'attributes["observation"] != nil and not IsMatch(attributes["observation"], "^(delivered|retry)$")'
        - 'attributes["resolution"] != nil and not IsMatch(attributes["resolution"], "^(released|expired|unauthorized|redundant|binding_failed|malformed)$")'
        - 'attributes["reject_code"] != nil and not IsMatch(attributes["reject_code"], "^(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|254|255)$")'
        - 'attributes["conflict"] != nil and not IsMatch(attributes["conflict"], "^(burn_block_delay|stacks_block_delay|miner_view)$")'
        - 'attributes["subsystem"] != nil and not IsMatch(attributes["subsystem"], "^(network_service|signer_state)$")'
        - 'attributes["reason"] != nil and not IsMatch(attributes["reason"], "^(none|canonical_view|local_node_rpc|other|peer_capability|inventory|queue_capacity|validation|retry_backoff|burn_block_arrival|stacks_block_arrival|inactive_miner|protocol_upgrade|miner_view_update|miner_parent_tenure_update|queue_full|export_failed)$")'
        - 'attributes["event"] != nil and not IsMatch(attributes["event"], "^(hello_accepted|hello_rejected|outbound_failure|resource_rejected|announcement_published|announcement_received|object_published|object_received|fetch_started|fetch_failed|durable_lookup|durable_hit|durable_miss|direct_push_sent|direct_push_received|direct_push_busy|direct_push_rejected|direct_push_failed|signer_received|signer_rejected|signer_equivocation|sync_request_sent|sync_request_received|sync_response_received|sync_failed|command_queue_full|event_queue_full|event_loop_stall|peer_store_write|peer_store_write_failed|peer_store_queue_full|peer_store_corruption_recovered)$")'
  transform/privacy:
    error_mode: propagate
    metric_statements:
      - context: resource
        statements:
          - keep_keys(resource.attributes, [])
      - context: datapoint
        statements:
          - keep_keys(datapoint.attributes, ${metricLabelKeys})
${resources}
  batch:
    send_batch_size: 512
    send_batch_max_size: 1024
    timeout: 2s

exporters:
  prometheus:
    endpoint: 0.0.0.0:9464
    resource_to_telemetry_conversion:
      enabled: true

service:
  extensions: [${actors.map(actor => `bearertokenauth/${actor.id}`).join(', ')}]
  telemetry:
    metrics:
      level: normal
      readers:
        - pull:
            exporter:
              prometheus:
                host: 0.0.0.0
                port: 8888
  pipelines:
${pipelines}
`;
}

export function buildTopology({signerCount, minerCount, followerCount}) {
  for (const [name, value, max] of [['signers', signerCount, LIMITS.signers], ['miners', minerCount, LIMITS.miners], ['followers', followerCount, LIMITS.followers]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error(`${name} must be within [1, ${max}]`);
  }
  const signers = SIGNERS.slice(0, signerCount);
  const actors = [];
  for (let index = 1; index <= minerCount; index++) actors.push({id: `poc-miner-${index}`, label: `Miner ${index}`, role: 'miner', type: 'node', service: `miner-${index}`, transportPeerId: NODE_IDENTITIES.miners[index - 1][1]});
  for (let index = 1; index <= signerCount; index++) {
    actors.push({id: `poc-signer-node-${index}`, label: `Signer ${index} companion`, role: 'companion', type: 'node', service: `signer-node-${index}`, transportPeerId: NODE_IDENTITIES.signerNodes[index - 1][1]});
    actors.push({id: `poc-signer-${index}`, label: `Signer ${index}`, role: 'signer', type: 'signer', service: `signer-${index}`, signerPublicKey: signers[index - 1][1], transportPeerId: SIGNER_TRANSPORT_PEER_IDS[index - 1], entityName: `PoC signer ${index}`, companionActorId: `poc-signer-node-${index}`});
  }
  for (let index = 1; index <= followerCount; index++) actors.push({id: `poc-follower-${index}`, label: `Outsider ${index}`, role: 'follower', type: 'node', service: `follower-${index}`, transportPeerId: NODE_IDENTITIES.followers[index - 1][1]});
  return {signerCount, minerCount, followerCount, signers, actors};
}

export function renderTopology(topology, output) {
  const configDir = join(output, 'configs');
  mkdirSync(configDir, {recursive: true});
  let services = 'services:\n';
  const volumes = [];
  for (let index = 1; index <= topology.minerCount; index++) {
    const name = `miner-${index}`;
    const file = `configs/${name}.toml`;
    writeFileSync(join(output, file), nodeConfig({
      name,
      identity: NODE_IDENTITIES.miners[index - 1],
      peerId: NODE_IDENTITIES.miners[index - 1][1],
      miner: true,
      mining: MINER_KEYS[index - 1],
      signers: topology.signers,
      connectionLimit: index === 1 ? CONNECTION_LIMITS.bootstrap : CONNECTION_LIMITS.miner,
    }));
    services += nodeService(name, `generated/${file}`, `${name}-data`, {
      primary: index === 1,
      delayedMiner: index > 1,
    });
    volumes.push(`${name}-data`);
  }
  for (let index = 1; index <= topology.signerCount; index++) {
    const nodeName = `signer-node-${index}`;
    const nodeFile = `configs/${nodeName}.toml`;
    const identity = NODE_IDENTITIES.signerNodes[index - 1];
    writeFileSync(join(output, nodeFile), nodeConfig({
      name: nodeName,
      identity,
      peerId: identity[1],
      miner: false,
      signers: topology.signers,
      connectionLimit: CONNECTION_LIMITS.actor,
      signerEventEndpoint: `signer-${index}:30000`,
    }));
    writeFileSync(
      join(configDir, `signer-${index}.toml`),
      signerConfig(
        index,
        topology.signers[index - 1],
        NODE_IDENTITIES.miners.slice(0, topology.minerCount),
      ),
    );
    services += nodeService(nodeName, `generated/${nodeFile}`, `${nodeName}-data`);
    services += signerService(index);
    volumes.push(`${nodeName}-data`, `signer-${index}-data`);
  }
  for (let index = 1; index <= topology.followerCount; index++) {
    const name = `follower-${index}`;
    const file = `configs/${name}.toml`;
    const identity = NODE_IDENTITIES.followers[index - 1];
    writeFileSync(join(output, file), nodeConfig({
      name,
      identity,
      peerId: identity[1],
      miner: false,
      signers: topology.signers,
      connectionLimit: CONNECTION_LIMITS.actor,
    }));
    services += nodeService(name, `generated/${file}`, `${name}-data`);
    volumes.push(`${name}-data`);
  }
  topology.actors.forEach((actor, index) => { services += telemetryService(actor, 4318 + index); });
  const compose = `name: stacks-libp2p-poc\n\n${services}\nvolumes:\n${volumes.map(name => `  ${name}:`).join('\n')}\n`;
  writeFileSync(join(output, 'compose.yaml'), compose);

  const enrollments = {
    version: 1,
    network: 'regtest',
    actors: topology.actors.map(({service: _service, type: _type, ...actor}) => actor),
    signerEntities: [],
  };
  writeFileSync(join(output, 'poc-enrollments.json'), `${JSON.stringify(enrollments, null, 2)}\n`);
  writeFileSync(join(output, 'collector.yaml'), collectorConfig(topology.actors));
  const env = [
    `STACKS_RPC_HOST=miner-1`,
    `STACKS_RPC_PORT=20443`,
    `STACKS_FOLLOWER_RPC_HOST=signer-node-1`,
    `STACKS_FOLLOWER_RPC_PORT=20443`,
    `EXPECTED_NATIVE_PEERS=${Math.min(8, topology.actors.length - 1)}`,
    `MINER_WALLETS=${Array.from({length: topology.minerCount}, (_, index) => `libp2p-poc-miner-${index + 1}`).join(',')}`,
    `MINER_BTC_ADDRS=${MINER_KEYS.slice(0, topology.minerCount).map(miner => miner[2]).join(',')}`,
    `POX5_SIGNER_ACCOUNTS=${topology.signers.map(signer => signer[2]).join(',')}`,
    `STACKING_KEYS=${topology.signers.map(signer => signer[0]).join(',')}`,
    `POC_NODE_SERVICES=${topology.actors.filter(actor => actor.type === 'node').map(actor => actor.service).join(',')}`,
    `POC_SIGNER_SERVICES=${topology.actors.filter(actor => actor.type === 'signer').map(actor => actor.service).join(',')}`,
  ].join('\n');
  writeFileSync(join(output, 'topology.env'), `${env}\n`);
  writeFileSync(
    join(output, 'manifest.json'),
    `${JSON.stringify({...topology, limits: LIMITS, connectionLimits: CONNECTION_LIMITS}, null, 2)}\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const topology = buildTopology({
    signerCount: numberOption('signers', 10, LIMITS.signers),
    minerCount: numberOption('miners', 3, LIMITS.miners),
    followerCount: numberOption('followers', 5, LIMITS.followers),
  });
  const outputArg = process.argv.find(arg => arg.startsWith('--output='))?.slice('--output='.length) ?? 'generated';
  const output = resolve(ROOT, outputArg);
  renderTopology(topology, output);
  console.log(`Generated ${topology.minerCount} miners, ${topology.signerCount} signer/companion pairs, ${topology.followerCount} outsider followers, and ${topology.actors.length} telemetry actors in ${output}`);
}
