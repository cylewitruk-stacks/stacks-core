# Attacknet image packaging

The attacknet Dockerfile deliberately keeps the workspace's `release-lite`
profile unchanged. That profile inherits `debug = true`, which remains useful
for release artifacts and does not need a workspace-wide semantic change just
to produce a compact disposable-network runtime image.

Instead, the image build separates each binary into two linked artifacts:

- the default runtime keeps the executable, its ordinary symbol table, and a
  GNU debuglink, but removes DWARF sections with `strip --strip-debug`;
- the optional `debug-symbols` target contains the full `.debug` files in the
  standard `/usr/lib/debug/bin` layout, plus a SHA-256 manifest covering both
  the corresponding runtime binaries and external symbols.

Build the normal image as before. To retain source/line debugging data, export
the symbols from the exact same source and build arguments and store the
artifact with the runtime image digest and BuildKit provenance:

```sh
docker buildx build \
  --file contrib/attacknet/images/cli/Dockerfile \
  --target debug-symbols \
  --output type=local,dest=attacknet-debug-symbols \
  .
```

The image labels and exported `BUILD-INFO` record the requested version, Git
revision/branch, Cargo profile, and strip mode. `SHA256SUMS` and the ELF
debuglink CRC provide the stronger binary-to-symbols pairing; labels or
`BUILD-INFO` alone are not proof that separately built artifacts match.

## Measured size basis

On the pre-compaction local arm64 image, Docker reported these uncompressed
binary layers:

| Binary | ELF size | DWARF sections | Estimated after `--strip-debug` |
| --- | ---: | ---: | ---: |
| `stacks-node` | 319,949,072 B | 279,896,770 B | about 40.1 MB |
| `stacks-signer` | 139,104,008 B | 122,646,553 B | about 16.5 MB |
| `stacks-inspect` | 210,504,648 B | 188,556,804 B | about 21.9 MB |

That removes roughly 591 MB from the three runtime ELF files before layer
compression. The exact post-build result will be slightly larger than the
table's subtraction because the GNU debuglink section is added after stripping.
This is a section-based estimate, not a substitute for recording the built OCI
size and digest in acceptance evidence.

## Runtime tradeoffs

The runtime stays on Debian slim and retains `ca-certificates` and `curl`.
Those are used for TLS/API communication, delayed startup, health checks, and
evidence collection; removing them or moving the Rust binaries from glibc to
musl would be a functional change rather than packaging-only compaction.

`--strip-debug` removes source paths, line tables, and local-variable DWARF from
the default image. Named backtraces remain more useful than with
`--strip-all`/`--strip-unneeded` because the ordinary symbol table is retained,
but full source/line debugging requires the matching external symbols.

The topology and run controllers are statically linked Go binaries in the same
distroless image recipe. Their build uses separate module and compiler cache
mounts, and each image selects one binary through the `BINARY` build argument.
The active probe remains a small Node image because its HTTP observation logic
is data-plane instrumentation rather than Kubernetes reconciliation.
