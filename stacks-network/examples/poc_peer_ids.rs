use stacks_common::util::hash::hex_bytes;
use stacks_network::{node_identity_from_seed, signer_identity_from_secret};
use stacks_network_types::NetworkScope;

fn main() {
    let scope = NetworkScope::new(0x8000_0000, 0x8000_0000);
    for (role, first, count) in [
        ("miner", 0x11_u8, 3_u8),
        ("signer-node", 0x21, 10),
        ("follower", 0x31, 5),
    ] {
        for offset in 0..count {
            let byte = first + offset;
            let seed = [byte; 32];
            let identity =
                node_identity_from_seed(&seed, scope).expect("valid deterministic PoC seed");
            println!(
                "{role}-{} {} {}",
                offset + 1,
                seed.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                identity.public().to_peer_id()
            );
        }
    }
    let decode = |encoded: &str| {
        hex_bytes(encoded)
            .expect("valid PoC signer secret hex")
            .try_into()
            .expect("32-byte PoC signer secret")
    };
    let signer_secrets: [[u8; 32]; 10] = [
        decode("41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc"),
        decode("9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee"),
        decode("3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb74"),
        [0x44; 32],
        [0x45; 32],
        [0x46; 32],
        [0x47; 32],
        [0x48; 32],
        [0x49; 32],
        [0x4a; 32],
    ];
    for (offset, secret) in signer_secrets.into_iter().enumerate() {
        let identity = signer_identity_from_secret(&secret, scope)
            .expect("valid deterministic PoC signer secret");
        println!("signer-{} {}", offset + 1, identity.public().to_peer_id());
    }
}
