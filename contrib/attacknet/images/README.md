# Attacknet images

Each subdirectory is one independently buildable image context or Dockerfile:

- [`cli/`](cli/) builds revision-specific Stacks node and signer binaries.
- [`probe/`](probe/) builds the credential-free actor probe.
- [`io-pressure/`](io-pressure/) builds the bounded I/O pressure helper.
- [`stacker/`](stacker/) builds the local regtest stacking helper.

Use `attacknet image build` for the supported local workflow. The Helm
development script consumes these same paths.
