# Development issues

This directory contains implementation plans grouped by Attacknet release.
The [`development roadmap`](../roadmap.md) remains the concise source for
priority and amendment status; issue documents preserve implementation detail.

## Releases

- [`r1/`](r1/): Release 1 amendments and follow-up work.

## Naming and scope

Issue filenames use:

```text
r<release-number>a<amendment-number>-<item-title>.md
```

An amendment may have one umbrella document and additional documents only for
independently implementable or reviewable items. Each document should state
status, dependencies, what, why, how, non-goals, and definition of done.

These files guide development. Updating them does not require a release review
packet unless the same change materially alters runtime behavior, safety,
Kubernetes APIs, evidence interpretation, or an advertised capability.
