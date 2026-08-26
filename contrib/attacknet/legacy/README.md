# Legacy qualification inputs

The supported Attacknet interface is the typed Go client and the
`testing.stacks.org/v1beta1` API. Shell and JavaScript retained in the parent
directory are internal qualification inputs for historical packets,
v1alpha1 conversion, or old/new equivalence. Their arguments and environment
variables are not an operator contract.

[`manifest.v1.json`](manifest.v1.json) records the stateful legacy helpers,
their authoritative Go owners, and the qualification reason each remains in
the tree. Runtime code must not dispatch to these files, and public examples
must not invoke them.

Historical release packet tooling remains under `../release/` because approved
packets bind exact paths and revisions. Frozen evidence-local scripts remain
with the evidence they produced. Neither category may be repurposed as a
runtime workflow.
