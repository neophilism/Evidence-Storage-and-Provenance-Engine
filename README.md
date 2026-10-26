# Evidence Storage and Provenance Engine

Standalone Node 24 TypeScript dependency library. Recovered foundation includes exact-byte acquisition, immutable revisions, quarantine/scans, selectors, source-family analysis, handling chains, redaction derivatives and encrypted local objects. No application implementation or research data.

## Checkpoint

Implementation: recovered foundation, not yet fully reviewed. Local validation: pending. CI: pending. Live acceptance: not performed. Initial code checkpoint precedes tests and packaging; do not treat this as a production release.

Shared contracts are vendored byte-identically from `engines/identity/src/contracts.ts`, provenance: `neophilism/Identity-Authorization-and-Policy-Engine` commit `2ecac5a7ec01e4470774ef545060b99dba38014d`. Recovery sources: `accountability-machine/packages/evidence/src/index.ts` and `accountability-machine/packages/runtime/src/objects.ts`; only relative contract imports were rewritten in this checkpoint. Originals were not modified.

Next: standalone strict TypeScript package/lock/CI, canonical PR registry, and synthetic boundary tests. Durable metadata transactions, identity integration and live service acceptance remain follow-up work.
