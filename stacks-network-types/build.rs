fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    std::env::set_var("PROTOC", protoc);

    prost_build::Config::new()
        .compile_protos(&["proto/stacks/network/v1/network.proto"], &["proto"])
        .expect("Stacks libp2p protocol schema compiles");

    println!("cargo:rerun-if-changed=proto/stacks/network/v1/network.proto");
}
