# Evidence Storage and Provenance Engine

Standalone Node 24 TypeScript dependency library for exact-byte acquisition, immutable revisions, quarantine/scans, revision-bound selectors, source-family analysis, handling chains, redaction derivatives and encrypted local objects. Synthetic fixtures only.

```sh
npm ci
npm run check
```

Import evidence functions from `@accountability/evidence`, local encrypted storage from `@accountability/evidence/objects`, and shared types from `@accountability/evidence/contracts`. `npm run build` produces ESM and declarations in `dist/`.

## Checkpoint

- Implementation: recovered foundation with two storage fixes (snapshot caller bytes before async work; reject symlinked tenant directories on read).
- Local validation: Node 24.22.1; strict typecheck, 21 automated tests, ESM/declaration build, registry validation and byte-identical contract comparison (including the pinned remote Identity commit) passed.
- CI validation: push and PR checks passed for implementation commit `200012f6aaadb0973504388bb79ab30a89fbb2b8`, including clean `npm ci` and `npm run check` ([run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40382672960)). Later documentation-only heads have separate runs on GitHub.
- Live acceptance: not performed. No deployed service, real scanner, durable metadata repository or identity integration is claimed.

Ready for review, one bounded foundation PR: [#1](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/1). The initial recovered code was pushed before packaging/tests in [28276f0](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/28276f04feddcf3579759a63c3df8ff526c759d4). The canonical machine-readable plan is [registry/prs.json](registry/prs.json); it describes only this authorized foundation unit.

## Provenance

`src/contracts.ts` is vendored byte-identically from `engines/identity/src/contracts.ts`, `neophilism/Identity-Authorization-and-Policy-Engine` commit `2ecac5a7ec01e4470774ef545060b99dba38014d`. Recovery sources were `accountability-machine/packages/evidence/src/index.ts` and `accountability-machine/packages/runtime/src/objects.ts`; their relative contract imports were rewritten. Original recovery files were not modified. The registry parser and pinned toolchain follow the local Identity foundation example; the parser was copied unchanged.

See [architecture and limits](docs/ARCHITECTURE.md) for consumer responsibilities and remaining integration work.

## Durable persistence WIP checkpoint

Recovered generic metadata/revision/audit/idempotency/outbox adapter and migration are now copied into this engine with Evidence-specific table/role names and local contracts imports. This is a code checkpoint before validation, not a supported production database interface yet. Source review and tests are pending, especially runtime login versus migration ownership, public raw SQL access, transaction scope mutation, immutable storage enforcement, optimistic revisions, atomic rollback/idempotency and expired final-attempt leases. No live infrastructure or service acceptance is claimed.

Recovery provenance: `accountability-machine/packages/runtime/src/database.ts` and `accountability-machine/migrations/001_foundation.sql`; originals are unchanged. This work follows foundation PR #1 and remains a separate bounded persistence PR.
