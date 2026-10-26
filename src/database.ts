import { Pool } from 'pg';
import type { Context, Json, AuditEvent, Revision, Scope } from './contracts.ts';
import { invariant, digest, newId, nonempty, validTime, requireScope } from './contracts.ts';

/** Trusted driver interface. Never expose a Query or Database to untrusted command handlers. */
export interface Query {
  query<T = Record<string, unknown>>(sql: string, values?: unknown[]): Promise<{ rows: T[] }>;
}
export interface Database {
  transaction<T>(fn: (q: Query) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
export function postgresDatabase(url: string): Database {
  const pool = new Pool({ connectionString: url, max: 10, connectionTimeoutMillis: 5000, statement_timeout: 10000 });
  return {
    async transaction<T>(fn: (q: Query) => Promise<T>): Promise<T> {
      const client = await pool.connect(); let broken = false;
      try {
        await client.query('BEGIN');
        const result = await fn({ query: async <R>(sql: string, values?: unknown[]) => ({ rows: (await client.query(sql, values)).rows as R[] }) });
        await client.query('COMMIT');
        return result;
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch { broken = true; }
        throw error;
      } finally { client.release(broken); }
    },
    close: () => pool.end(),
  };
}

/** Check the authenticated login, not just current_user after lowering its role. */
export async function assertRuntimeConnection(q: Query): Promise<void> {
  const result = await q.query<{ safe: boolean }>(`
    SELECT session_user = current_user AND login.rolcanlogin
      AND NOT login.rolsuper AND NOT login.rolbypassrls AND NOT login.rolcreatedb
      AND NOT login.rolcreaterole AND NOT login.rolreplication
      AND pg_has_role(session_user, runtime.oid, 'MEMBER')
      AND NOT runtime.rolcanlogin AND NOT runtime.rolsuper AND NOT runtime.rolbypassrls
      AND NOT runtime.rolcreatedb AND NOT runtime.rolcreaterole AND NOT runtime.rolreplication
      AND NOT runtime.rolinherit
      AND NOT has_schema_privilege(session_user, 'public', 'CREATE')
      AND NOT EXISTS (SELECT FROM pg_roles r WHERE
        (r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication)
        AND pg_has_role(session_user, r.oid, 'MEMBER'))
      AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname LIKE 'evidence\\_%' ESCAPE '\\'
        AND pg_has_role(session_user, c.relowner, 'MEMBER')) AS safe
    FROM pg_roles login CROSS JOIN pg_roles runtime
    WHERE login.rolname = session_user AND runtime.rolname = 'evidence_runtime'`);
  invariant(result.rows[0]?.safe === true, 'unsafe_database_role', 'Use a restricted login with only the Evidence runtime role, never a migration/owner login');
}

function snapshotContext(ctx: Context): Context {
  const copy = structuredClone(ctx);
  nonempty(copy.tenantId, 'tenantId', 128); nonempty(copy.projectId, 'projectId', 128);
  nonempty(copy.actor.id, 'actorId', 128); nonempty(copy.requestId, 'requestId', 128);
  nonempty(copy.purpose, 'purpose', 128); validTime(copy.now);
  invariant(['human', 'agent', 'service'].includes(copy.actor.kind) && Array.isArray(copy.actor.roles), 'invalid_input', 'Invalid actor');
  copy.actor.roles.forEach(role => nonempty(role, 'role', 128));
  Object.freeze(copy.actor.roles); Object.freeze(copy.actor); return Object.freeze(copy);
}
export async function scoped<T>(db: Database, ctx: Context, fn: (tx: UnitOfWork) => Promise<T>): Promise<T> {
  const captured = snapshotContext(ctx);
  return db.transaction(async q => {
    await assertRuntimeConnection(q);
    await q.query('SET LOCAL ROLE evidence_runtime');
    await q.query("SELECT set_config('evidence.tenant_id',$1,true), set_config('evidence.project_id',$2,true)", [captured.tenantId, captured.projectId]);
    const lifecycle: Lifecycle = { active: true, failed: false, pending: new Set() };
    const guarded: Query = { query: (sql, values) => { invariant(lifecycle.active, 'transaction_aborted', 'Transaction is closed'); return q.query(sql, values); } };
    const tx = new UnitOfWork(guarded, captured, lifecycle);
    try { const result = await fn(tx); invariant(lifecycle.active && !lifecycle.failed && lifecycle.pending.size === 0, 'transaction_aborted', 'An operation failed or was not awaited'); return result; }
    finally { lifecycle.active = false; await Promise.allSettled([...lifecycle.pending]); }
  });
}

interface Lifecycle { active: boolean; failed: boolean; pending: Set<Promise<unknown>>; }
export class UnitOfWork {
  #q: Query; #ctx: Context; #lifecycle: Lifecycle;
  constructor(q: Query, ctx: Context, lifecycle: Lifecycle) {
    this.#q = q; this.#ctx = snapshotContext(ctx); this.#lifecycle = lifecycle;
  }
  #check(): void { invariant(this.#lifecycle.active && !this.#lifecycle.failed, 'transaction_aborted', 'Transaction is closed or an operation failed'); }
  async #run<T>(fn: () => Promise<T>): Promise<T> {
    this.#check();
    const work = fn(); this.#lifecycle.pending.add(work);
    try { return await work; } catch (error) { this.#lifecycle.failed = true; throw error; }
    finally { this.#lifecycle.pending.delete(work); }
  }
  #scope(): [string, string] { return [this.#ctx.tenantId, this.#ctx.projectId]; }
  async #ensureProject(): Promise<void> {
    await this.#q.query('INSERT INTO public.evidence_project(tenant_id,project_id) VALUES($1,$2) ON CONFLICT DO NOTHING', this.#scope());
  }
  async #lock(): Promise<void> {
    await this.#ensureProject();
    await this.#q.query('SELECT project_id FROM public.evidence_project WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE', this.#scope());
  }
  async #get<T>(kind: string, id: string, revision?: number): Promise<Revision<T> | null> {
    nonempty(kind, 'kind', 64); nonempty(id, 'id', 128);
    invariant(revision === undefined || (Number.isSafeInteger(revision) && revision > 0), 'invalid_revision', 'Revision must be positive');
    const result = await this.#q.query<RecordRow<T>>(revision === undefined
      ? 'SELECT r.* FROM public.evidence_record r JOIN public.evidence_head h USING(tenant_id,project_id,kind,id,revision) WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.kind=$3 AND r.id=$4'
      : 'SELECT * FROM public.evidence_record WHERE tenant_id=$1 AND project_id=$2 AND kind=$3 AND id=$4 AND revision=$5',
    revision === undefined ? [...this.#scope(), kind, id] : [...this.#scope(), kind, id, revision]);
    const row = result.rows[0]; return row ? this.#revision(kind, id, row) : null;
  }
  #revision<T>(kind: string, id: string, row: RecordRow<T>): Revision<T> {
    return { tenantId: this.#ctx.tenantId, projectId: this.#ctx.projectId, id, kind, revision: row.revision, value: row.value, createdAt: new Date(row.created_at).toISOString(), actorId: row.actor_id };
  }
  get<T>(kind: string, id: string, revision?: number): Promise<Revision<T> | null> {
    return this.#run(() => this.#get<T>(kind, id, revision));
  }
  list<T>(kind: string, limit = 100, after = ''): Promise<Revision<T>[]> {
    return this.#run(async () => {
      nonempty(kind, 'kind', 64); invariant(Number.isSafeInteger(limit) && limit > 0 && limit <= 500, 'invalid_limit', 'Limit must be 1-500');
      const result = await this.#q.query<RecordRow<T> & { id: string }>('SELECT r.* FROM public.evidence_record r JOIN public.evidence_head h USING(tenant_id,project_id,kind,id,revision) WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.kind=$3 AND r.id>$4 ORDER BY r.id LIMIT $5', [...this.#scope(), kind, after, limit]);
      return result.rows.map(row => this.#revision(kind, row.id, row));
    });
  }
  put<T>(kind: string, id: string, expectedRevision: number, value: T): Promise<Revision<T>> {
    // Capture JSON before asynchronous lock acquisition.
    return this.#run(async () => {
      nonempty(kind, 'kind', 64); nonempty(id, 'id', 128);
      invariant(Number.isSafeInteger(expectedRevision) && expectedRevision >= 0 && expectedRevision < 2147483647, 'invalid_revision', 'Expected revision must be a nonnegative integer');
      const captured = structuredClone(value); const valueHash = digest(captured);
      await this.#lock();
      const current = await this.#get<T>(kind, id);
      invariant((current?.revision ?? 0) === expectedRevision, 'revision_conflict', 'Resource revision changed');
      const revision = expectedRevision + 1;
      await this.#q.query('INSERT INTO public.evidence_record(tenant_id,project_id,kind,id,revision,value,created_at,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [...this.#scope(), kind, id, revision, JSON.stringify(captured), this.#ctx.now, this.#ctx.actor.id]);
      await this.#q.query('INSERT INTO public.evidence_head(tenant_id,project_id,kind,id,revision) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,project_id,kind,id) DO UPDATE SET revision=EXCLUDED.revision', [...this.#scope(), kind, id, revision]);
      await this.#audit('record.revised', { kind, id, revision, valueHash });
      return { tenantId: this.#ctx.tenantId, projectId: this.#ctx.projectId, id, kind, revision, value: captured, createdAt: new Date(this.#ctx.now).toISOString(), actorId: this.#ctx.actor.id };
    });
  }
  async #audit(type: string, payload: Json): Promise<AuditEvent> {
    nonempty(type, 'audit type', 128); const captured = structuredClone(payload); digest(captured);
    await this.#lock();
    const result = await this.#q.query<{ audit_sequence: string | number; audit_hash: string }>('SELECT audit_sequence,audit_hash FROM public.evidence_project WHERE tenant_id=$1 AND project_id=$2', this.#scope());
    const head = result.rows[0]!; const sequence = Number(head.audit_sequence) + 1;
    invariant(Number.isSafeInteger(sequence), 'audit_overflow', 'Audit sequence exceeds safe integer range');
    const base = { tenantId: this.#ctx.tenantId, projectId: this.#ctx.projectId, id: newId(), sequence, type, actorId: this.#ctx.actor.id, at: new Date(this.#ctx.now).toISOString(), requestId: this.#ctx.requestId, payload: captured, previousHash: head.audit_hash };
    const hash = digest(base);
    await this.#q.query('INSERT INTO public.evidence_audit(tenant_id,project_id,sequence,id,type,actor_id,at,request_id,payload,previous_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)', [...this.#scope(), sequence, base.id, type, base.actorId, base.at, base.requestId, JSON.stringify(captured), base.previousHash, hash]);
    await this.#q.query('UPDATE public.evidence_project SET audit_sequence=$3,audit_hash=$4 WHERE tenant_id=$1 AND project_id=$2', [...this.#scope(), sequence, hash]);
    return { ...base, hash };
  }
  audit(type: string, payload: Json): Promise<AuditEvent> { return this.#run(() => this.#audit(type, payload)); }
  audits(): Promise<AuditEvent[]> {
    return this.#run(async () => {
      const result = await this.#q.query<AuditRow>('SELECT * FROM public.evidence_audit WHERE tenant_id=$1 AND project_id=$2 ORDER BY sequence', this.#scope());
      return result.rows.map(row => ({ tenantId: this.#ctx.tenantId, projectId: this.#ctx.projectId, id: row.id, sequence: Number(row.sequence), type: row.type, actorId: row.actor_id, at: new Date(row.at).toISOString(), requestId: row.request_id, payload: row.payload, previousHash: row.previous_hash, hash: row.hash }));
    });
  }
  idempotent<T extends Json>(key: string, input: Json, fn: () => Promise<T>): Promise<T> {
    return this.#run(async () => {
      nonempty(key, 'idempotency key', 200); const fingerprint = digest(input); await this.#lock();
      const result = await this.#q.query<{ fingerprint: string; result: T }>('SELECT fingerprint,result FROM public.evidence_idempotency WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND key=$4', [...this.#scope(), this.#ctx.actor.id, key]);
      const prior = result.rows[0];
      if (prior) { invariant(prior.fingerprint === fingerprint, 'idempotency_conflict', 'Key already used for different command'); return prior.result; }
      const value = structuredClone(await fn()); this.#check(); digest(value);
      await this.#q.query('INSERT INTO public.evidence_idempotency(tenant_id,project_id,actor_id,key,fingerprint,result) VALUES($1,$2,$3,$4,$5,$6)', [...this.#scope(), this.#ctx.actor.id, key, fingerprint, JSON.stringify(value)]);
      return value;
    });
  }
  enqueue(topic: string, payload: Json, id = newId(), maxAttempts = 5): Promise<string> {
    return this.#run(async () => {
      nonempty(topic, 'topic', 128); nonempty(id, 'job id', 128);
      invariant(Number.isSafeInteger(maxAttempts) && maxAttempts > 0 && maxAttempts <= 100, 'invalid_attempts', 'Maximum attempts must be 1-100');
      const captured = structuredClone(payload); const fingerprint = digest(captured); await this.#lock();
      await this.#q.query('INSERT INTO public.evidence_outbox(tenant_id,project_id,id,topic,payload,available_at,max_attempts) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING', [...this.#scope(), id, topic, JSON.stringify(captured), this.#ctx.now, maxAttempts]);
      const existing = await this.#q.query<{ topic: string; payload: Json; max_attempts: number }>('SELECT topic,payload,max_attempts FROM public.evidence_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3', [...this.#scope(), id]);
      const job = existing.rows[0]!;
      invariant(job.topic === topic && digest(job.payload) === fingerprint && job.max_attempts === maxAttempts, 'outbox_conflict', 'Job ID already used for a different message'); return id;
    });
  }
  claim(worker: string, leaseMs = 30000, topic?: string): Promise<LeasedJob | null> {
    return this.#run(async () => {
      nonempty(worker, 'worker', 128); if (topic !== undefined) nonempty(topic, 'topic', 128); invariant(Number.isSafeInteger(leaseMs) && leaseMs >= 1000 && leaseMs <= 300000, 'invalid_lease', 'Lease must be 1-300 seconds');
      await this.#lock();
      await this.#q.query("UPDATE public.evidence_outbox SET state='dead',lease_until=NULL,lease_owner=NULL,last_error='attempts_exhausted' WHERE tenant_id=$1 AND project_id=$2 AND attempts>=max_attempts AND ($4::text IS NULL OR topic=$4) AND (state='pending' OR (state='leased' AND lease_until<=$3))", [...this.#scope(), this.#ctx.now, topic ?? null]);
      const result = await this.#q.query<JobRow>(`WITH next AS (SELECT id FROM public.evidence_outbox WHERE tenant_id=$1 AND project_id=$2 AND attempts<max_attempts AND ($6::text IS NULL OR topic=$6) AND ((state='pending' AND available_at<=$3) OR (state='leased' AND lease_until<=$3)) ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE public.evidence_outbox SET state='leased',generation=generation+1,attempts=attempts+1,lease_owner=$4,lease_until=$5 WHERE tenant_id=$1 AND project_id=$2 AND id IN(SELECT id FROM next) RETURNING *`, [...this.#scope(), this.#ctx.now, worker, new Date(validTime(this.#ctx.now) + leaseMs).toISOString(), topic ?? null]);
      const job = result.rows[0]; return job ? { tenantId: this.#ctx.tenantId, projectId: this.#ctx.projectId, id: job.id, topic: job.topic, payload: job.payload, generation: job.generation, attempts: job.attempts, leaseOwner: worker } : null;
    });
  }
  acknowledge(job: LeasedJob): Promise<void> {
    return this.#run(async () => {
      validateLease(job, this.#ctx);
      const result = await this.#q.query("UPDATE public.evidence_outbox SET state='completed',lease_until=NULL,lease_owner=NULL WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND state='leased' AND generation=$4 AND lease_owner=$5 AND lease_until>$6 RETURNING id", [...this.#scope(), job.id, job.generation, job.leaseOwner, this.#ctx.now]);
      invariant(result.rows.length === 1, 'stale_lease', 'Lease expired or superseded');
    });
  }
  fail(job: LeasedJob, code: string, retryMs = 1000): Promise<void> {
    return this.#run(async () => {
      validateLease(job, this.#ctx); invariant(/^[a-z0-9_]{1,64}$/.test(code), 'invalid_error', 'Use a bounded error code');
      invariant(Number.isSafeInteger(retryMs) && retryMs >= 0 && retryMs <= 3600000, 'invalid_retry', 'Retry must be 0-3600 seconds');
      const result = await this.#q.query("UPDATE public.evidence_outbox SET state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'pending' END,lease_until=NULL,lease_owner=NULL,last_error=$6,available_at=$7 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND state='leased' AND generation=$4 AND lease_owner=$5 AND lease_until>$8 RETURNING id", [...this.#scope(), job.id, job.generation, job.leaseOwner, code, new Date(validTime(this.#ctx.now) + retryMs).toISOString(), this.#ctx.now]);
      invariant(result.rows.length === 1, 'stale_lease', 'Lease expired or superseded');
    });
  }
}
interface RecordRow<T> { revision: number; value: T; created_at: Date | string; actor_id: string; }
interface AuditRow { id: string; sequence: string | number; type: string; actor_id: string; at: string | Date; request_id: string; payload: Json; previous_hash: string; hash: string; }
interface JobRow { id: string; topic: string; payload: Json; generation: number; attempts: number; }
export interface LeasedJob extends JobRow, Scope { leaseOwner: string; }
function validateLease(job: LeasedJob, scope: Scope): void {
  requireScope(scope, job);
  nonempty(job.id, 'job id', 128); nonempty(job.leaseOwner, 'lease owner', 128);
  invariant(Number.isSafeInteger(job.generation) && job.generation > 0, 'invalid_lease', 'Positive lease generation required');
}
export function verifyAudit(events: readonly AuditEvent[]): boolean {
  let previous = ''; let sequence = 0; const scope = events[0];
  try {
    for (const event of events) {
      const { hash, ...base } = event;
      if (event.tenantId !== scope?.tenantId || event.projectId !== scope?.projectId || event.sequence !== ++sequence || event.previousHash !== previous || digest(base) !== hash) return false;
      previous = hash;
    }
    return true;
  } catch { return false; }
}
