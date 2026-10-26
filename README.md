# Evidence Storage and Provenance Engine

Standalone Node 24 TypeScript dependency library for exact-byte acquisition, immutable revisions, quarantine/scans, revision-bound selectors, source-family analysis, handling chains, redaction derivatives and encrypted local objects. Synthetic fixtures only.

```sh
npm ci
npm run check
```

Import evidence functions from `@accountability/evidence`, local encrypted storage from `@accountability/evidence/objects`, and shared types from `@accountability/evidence/contracts`. `npm run build` produces ESM and declarations in `dist/`.

## Foundation checkpoint (PR #1)

- Implementation: recovered foundation with two storage fixes (snapshot caller bytes before async work; reject symlinked tenant directories on read).
- Local validation: Node 24.22.1; strict typecheck, 21 automated tests, ESM/declaration build, registry validation and byte-identical contract comparison (including the pinned remote Identity commit) passed.
- CI validation: push and PR checks passed for implementation commit `200012f6aaadb0973504388bb79ab30a89fbb2b8`, including clean `npm ci` and `npm run check` ([run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40382672960)). Later documentation-only heads have separate runs on GitHub.
- Live acceptance: not performed. No deployed service, real scanner or identity integration is claimed.

Ready for review, one bounded foundation PR: [#1](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/1). The initial recovered code was pushed before packaging/tests in [28276f0](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/28276f04feddcf3579759a63c3df8ff526c759d4). The canonical machine-readable plan is [registry/prs.json](registry/prs.json); it describes only this authorized foundation unit.

## Provenance

`src/contracts.ts` is vendored byte-identically from `engines/identity/src/contracts.ts`, `neophilism/Identity-Authorization-and-Policy-Engine` commit `2ecac5a7ec01e4470774ef545060b99dba38014d`. Recovery sources were `accountability-machine/packages/evidence/src/index.ts` and `accountability-machine/packages/runtime/src/objects.ts`; their relative contract imports were rewritten. Original recovery files were not modified. The registry parser and pinned toolchain follow the local Identity foundation example; the parser was copied unchanged.

See [architecture and limits](docs/ARCHITECTURE.md) for consumer responsibilities and remaining integration work.

## Durable scoped persistence checkpoint

Import `postgresDatabase`, `scoped` and `verifyAudit` from `@accountability/evidence/database`. The package includes `migrations/001_foundation.sql`; apply it once as a separate migration owner to a dedicated Evidence database. Connect the application through a restricted LOGIN granted the NOLOGIN `evidence_runtime` role. Privileged/owner connections are rejected before SET ROLE. See [SQL review and deployment contract](docs/SQL_REVIEW.md).

The adapter stores generic scoped metadata snapshots and immutable revisions, chained audits, actor/input-bound idempotency results and generation-fenced outbox jobs in one PostgreSQL transaction. It uses project-row locks and expected revisions, keeps raw SQL private, captures caller context/JSON before awaits, and rejects caught failures or unawaited operations at commit. Outbox completion/failure checks scope, owner, generation and lease deadline; expired final-attempt jobs become dead.

- Implementation: durable persistence foundation in ready-for-review [PR #2](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/2), initially pinned to foundation head `24d8440589648783263934216d9fac202ab3480a`.
- Local validation: strict typecheck, **39 tests** (18 persistence integration tests plus 21 foundation tests), ESM/declaration build and canonical registry validation passed on Node 24.22.1. PGlite applies the actual migration, exercises roles/RLS and persists across a filesystem restart.
- CI validation: push and PR checks passed for implementation commit `6464615b423ec95ed0293f6b8b0e2db291ea120b` ([PR run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40384840936)). Later documentation-only heads have separate GitHub runs.
- Live acceptance: not performed; no external infrastructure was created. PGlite is not proof of production authentication, network pooling or true multi-session locking.

Recovery provenance: `accountability-machine/packages/runtime/src/database.ts` and `accountability-machine/migrations/001_foundation.sql`; originals are unchanged. The first WIP code checkpoint was pushed in [ce22563](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/ce22563b6cd3066587bbee066942672dda7f1a4c) before hardening and tests. Evidence-prefixed tables/role and local contracts imports isolate the recovered generic persistence layer from application storage.

Next coordinated work: Identity-gated service operations, production PostgreSQL acceptance (including independent-session locking and runtime login provisioning), object/metadata reconciliation, durable audit anchoring, retention/key lifecycle and scanner/worker integration.

## ESP-003 facade WIP checkpoint

Initial authenticated application facade composes the immutable Evidence domain, scoped Database and encrypted object store. Identity SDK source is pinned to upstream main; scope/actor come from authenticate, never command fields. Acquisition metadata and the scan outbox entry share a transaction. This checkpoint precedes tests: durable scan attempt handling, trusted worker/scanner ports, orphan reconciliation, final validation and compiled package exports are pending. Blob writes may outlive SQL rollback; this WIP does not delete blobs. No live service/scanner acceptance is claimed.
