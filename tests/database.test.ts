import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PGlite} from '@electric-sql/pglite';
import {scoped,verifyAudit,assertRuntimeConnection,type Database,type Query,type LeasedJob,type UnitOfWork} from '../src/database.ts';
import {DomainError,digest,type Context} from '../src/contracts.ts';

const ctx:Context={tenantId:'tenant-fixture',projectId:'project-fixture',actor:{id:'actor-fixture',kind:'human',roles:[]},purpose:'verify-fixture',requestId:'request-fixture',now:'2026-01-01T00:00:00.000Z'};
const at=(ms:number):Context=>({...ctx,now:new Date(Date.parse(ctx.now)+ms).toISOString()});
const code=(expected:string)=>(error:unknown)=>error instanceof DomainError && error.code===expected;
const migration=await readFile(new URL('../migrations/001_foundation.sql',import.meta.url),'utf8');
function adapter(pg:PGlite):Database {
  return {transaction:fn=>pg.transaction(tx=>fn({query:async<T>(sql:string,values?:unknown[])=>({rows:(await tx.query(sql,values)).rows as T[]})})),close:()=>pg.close()};
}
async function setup(t:{after:(fn:()=>Promise<void>)=>void},login=true){
  const pg=new PGlite();t.after(()=>pg.close());await pg.exec(migration);
  await pg.exec('CREATE ROLE evidence_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO evidence_test_login;');
  if(login)await pg.exec('SET SESSION AUTHORIZATION evidence_test_login');
  return {pg,db:adapter(pg)};
}
async function raw<T>(db:Database,scope:Context,fn:(q:Query)=>Promise<T>):Promise<T>{
  return db.transaction(async q=>{
    await q.query('SET LOCAL ROLE evidence_runtime');
    await q.query("SELECT set_config('evidence.tenant_id',$1,true),set_config('evidence.project_id',$2,true)",[scope.tenantId,scope.projectId]);
    return fn(q);
  });
}

test('migration enables FORCE RLS on all scoped tables; fresh login has no unscoped access',async t=>{
  const {db,pg}=await setup(t);
  const catalog=await pg.query<{relname:string;relrowsecurity:boolean;relforcerowsecurity:boolean}>("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname IN ('evidence_project','evidence_record','evidence_head','evidence_audit','evidence_idempotency','evidence_outbox')");
  assert.equal(catalog.rows.length,6);assert.ok(catalog.rows.every(r=>r.relrowsecurity&&r.relforcerowsecurity));
  await scoped(db,ctx,async tx=>{await tx.put('evidence','original',0,{sha256:'synthetic-hash'});await tx.enqueue('scan',{id:'original'},'job');});
  await db.transaction(async q=>{await q.query('SET LOCAL ROLE evidence_runtime');
    for(const table of ['project','record','head','audit','idempotency','outbox'])assert.equal((await q.query(`SELECT * FROM public.evidence_${table}`)).rows.length,0);
  });
  await assert.rejects(db.transaction(async q=>{await q.query('SET LOCAL ROLE evidence_runtime');await q.query("INSERT INTO public.evidence_project(tenant_id,project_id) VALUES('x','y')");}),/row-level security/);
  const role=await pg.query<{name:string}>('SELECT current_user AS name');assert.equal(role.rows[0]!.name,'evidence_test_login');
});

for(const change of [{tenantId:'other-tenant'},{projectId:'other-project'}])test(`RLS hides all metadata, audit, idempotency and jobs across ${Object.keys(change)[0]}`,async t=>{
  const {db}=await setup(t);const foreign={...ctx,...change};
  await scoped(db,ctx,tx=>tx.idempotent('command',{input:1},async()=>{await tx.put('evidence','same-id',0,{revision:'original'});await tx.enqueue('scan',{},'same-job');return {done:true};}));
  await scoped(db,foreign,async tx=>{assert.equal(await tx.get('evidence','same-id'),null);assert.deepEqual(await tx.list('evidence'),[]);assert.deepEqual(await tx.audits(),[]);assert.equal(await tx.claim('worker'),null);});
  for(const table of ['project','record','head','audit','idempotency','outbox'])await raw(db,foreign,async q=>assert.equal((await q.query(`SELECT * FROM public.evidence_${table}`)).rows.length,table==='project'?1:0));
  await assert.rejects(raw(db,ctx,q=>q.query('INSERT INTO public.evidence_project(tenant_id,project_id) VALUES($1,$2)',[foreign.tenantId,foreign.projectId])),/row-level security/);
  await assert.rejects(raw(db,ctx,q=>q.query('UPDATE public.evidence_outbox SET lease_owner=$1 WHERE id=$2',['other','same-job'])),/check constraint/);
  await raw(db,foreign,async q=>assert.equal((await q.query("UPDATE public.evidence_outbox SET state='dead' WHERE id='same-job' RETURNING id")).rows.length,0));
  await scoped(db,foreign,tx=>tx.put('evidence','same-id',0,{revision:'isolated'}));
  assert.deepEqual((await scoped(db,ctx,tx=>tx.get('evidence','same-id')))?.value,{revision:'original'});
});

test('runtime and owner cannot mutate originals/audit/idempotency or rewind heads',async t=>{
  const {db,pg}=await setup(t);
  await scoped(db,ctx,tx=>tx.idempotent('key',{},async()=>{await tx.put('evidence','source',0,{bytes:'original'});await tx.put('evidence','source',1,{bytes:'replacement'});return true;}));
  for(const sql of ["UPDATE public.evidence_record SET value='{}'","DELETE FROM public.evidence_record","DELETE FROM public.evidence_audit","UPDATE public.evidence_audit SET type='changed'","DELETE FROM public.evidence_idempotency","TRUNCATE public.evidence_record CASCADE","DROP TABLE public.evidence_record CASCADE","ALTER TABLE public.evidence_record DISABLE ROW LEVEL SECURITY"]){
    await assert.rejects(raw(db,ctx,q=>q.query(sql)),/permission denied|must be owner/);
  }
  await assert.rejects(raw(db,ctx,q=>q.query("UPDATE public.evidence_head SET revision=1 WHERE id='source'")),/advance exactly one/);
  await assert.rejects(raw(db,ctx,q=>q.query("UPDATE public.evidence_project SET audit_sequence=0,audit_hash=''")),/cannot rewind/);
  await assert.rejects(raw(db,ctx,q=>q.query("INSERT INTO public.evidence_record(tenant_id,project_id,kind,id,revision,value,created_at,actor_id) VALUES($1,$2,'evidence','source',4,'{}',$3,'fixture')",[ctx.tenantId,ctx.projectId,ctx.now])),/append to the current head/);
  await pg.exec('SET SESSION AUTHORIZATION postgres');
  // Even the migration owner hits immutability triggers unless it explicitly changes the schema.
  for(const sql of ["UPDATE public.evidence_record SET value='{}'","DELETE FROM public.evidence_audit","TRUNCATE public.evidence_idempotency"]){await assert.rejects(pg.exec(sql),/immutable/);}
  await pg.exec('SET SESSION AUTHORIZATION evidence_test_login');
  await scoped(db,ctx,async tx=>{assert.deepEqual((await tx.get('evidence','source',1))?.value,{bytes:'original'});assert.equal((await tx.get('evidence','source'))?.revision,2);assert.ok(verifyAudit(await tx.audits()));});
});

test('optimistic revisions have one winner, immutable history and stable pagination',async t=>{
  const {db}=await setup(t);await scoped(db,ctx,tx=>tx.put('evidence','source',0,{value:1}));
  const outcomes=await Promise.allSettled([scoped(db,ctx,tx=>tx.put('evidence','source',1,{value:2})),scoped(db,ctx,tx=>tx.put('evidence','source',1,{value:3}))]);
  assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);assert.equal(outcomes.filter(r=>r.status==='rejected'&&code('revision_conflict')(r.reason)).length,1);
  await scoped(db,ctx,async tx=>{assert.equal((await tx.get('evidence','source'))?.revision,2);assert.deepEqual((await tx.get('evidence','source',1))?.value,{value:1});await tx.put('evidence','z',0,{});assert.deepEqual((await tx.list('evidence',1,'source')).map(r=>r.id),['z']);});
  await assert.rejects(scoped(db,ctx,tx=>tx.put('evidence','source',1.5,{})),code('invalid_revision'));
});

test('record, revision head, audit, idempotency and outbox roll back atomically and permit retry',async t=>{
  const {db}=await setup(t);
  const command=(abort:boolean)=>scoped(db,ctx,tx=>tx.idempotent('atomic',{input:1},async()=>{
    await tx.put('evidence','source',0,{value:'original'});await tx.enqueue('scan',{id:'source'},'job');if(abort)throw new Error('fixture_abort');return {id:'source'};
  }));
  await assert.rejects(command(true),/fixture_abort/);
  await raw(db,ctx,async q=>{for(const table of ['project','record','head','audit','idempotency','outbox'])assert.equal((await q.query(`SELECT * FROM public.evidence_${table}`)).rows.length,0);});
  assert.deepEqual(await command(false),{id:'source'});assert.deepEqual(await command(false),{id:'source'});
  await scoped(db,ctx,async tx=>{assert.equal((await tx.audits()).length,1);assert.equal((await tx.get('evidence','source'))?.revision,1);assert.ok(await tx.claim('worker'));});
});

test('caught domain failures poison the transaction so earlier writes cannot commit',async t=>{
  const {db}=await setup(t);
  await assert.rejects(scoped(db,ctx,async tx=>{await tx.put('evidence','source',0,{});try{await tx.put('evidence','source',0,{});}catch{};}),code('transaction_aborted'));
  assert.equal(await scoped(db,ctx,tx=>tx.get('evidence','source')),null);
});

test('idempotency is actor-scoped, canonical, input-bound and rolls back conflicted side effects',async t=>{
  const {db}=await setup(t);let runs=0;
  const command=(context:Context,input:{a:number;b:number})=>scoped(db,context,tx=>tx.idempotent('key',input,async()=>{runs++;await tx.audit('fixture.command',{runs});return {runs};}));
  assert.deepEqual(await command(ctx,{a:1,b:2}),await command(ctx,{b:2,a:1}));assert.equal(runs,1);
  await assert.rejects(command(ctx,{a:2,b:2}),code('idempotency_conflict'));
  await command({...ctx,actor:{...ctx.actor,id:'other-actor'}},{a:1,b:2});assert.equal(runs,2);
  assert.equal((await scoped(db,ctx,tx=>tx.audits())).length,2);
  await scoped(db,ctx,tx=>tx.enqueue('scan',{a:1},'same'));
  await scoped(db,ctx,tx=>tx.enqueue('scan',{a:1},'same'));
  await assert.rejects(scoped(db,ctx,async tx=>{await tx.put('evidence','rolled-back',0,{});await tx.enqueue('scan',{a:2},'same');}),code('outbox_conflict'));
  assert.equal(await scoped(db,ctx,tx=>tx.get('evidence','rolled-back')),null);
});

test('audit verification detects tampered, reordered, missing-prefix and mixed-scope events',async t=>{
  const {db}=await setup(t);await scoped(db,ctx,async tx=>{await tx.audit('fixture.a',{a:1});await tx.audit('fixture.b',{b:2});});
  const events=await scoped(db,ctx,tx=>tx.audits());assert.ok(verifyAudit(events));
  const tampered=structuredClone(events);tampered[0]!.payload={changed:true};assert.equal(verifyAudit(tampered),false);
  assert.equal(verifyAudit([...events].reverse()),false);assert.equal(verifyAudit(events.slice(1)),false);
  const mixed=structuredClone(events);Object.assign(mixed[1]!,{tenantId:'other'});const {hash,...body}=mixed[1]!;mixed[1]!.hash=digest(body);assert.equal(verifyAudit(mixed),false);
});

test('expired lease reclaim increments generation and rejects old acknowledgements/failures and wrong owners',async t=>{
  const {db}=await setup(t);await scoped(db,ctx,tx=>tx.enqueue('scan',{},'job'));
  const first=await scoped(db,ctx,tx=>tx.claim('worker-a',1000));assert.ok(first);
  assert.equal(await scoped(db,ctx,tx=>tx.claim('worker-b',1000)),null);
  const second=await scoped(db,at(1000),tx=>tx.claim('worker-b',1000));assert.ok(second);assert.equal(second.generation,2);assert.equal(second.attempts,2);
  for(const job of [first,{...second,leaseOwner:'wrong-owner'}]){
    await assert.rejects(scoped(db,at(1000),tx=>tx.acknowledge(job)),code('stale_lease'));
    await assert.rejects(scoped(db,at(1000),tx=>tx.fail(job,'fixture_failure')),code('stale_lease'));
  }
  await scoped(db,at(1000),tx=>tx.acknowledge(second));assert.equal(await scoped(db,at(3000),tx=>tx.claim('worker-c')),null);
});

test('lease expiry at the exact boundary cannot acknowledge; exhausted leases become dead without a final callback',async t=>{
  const {db}=await setup(t);await scoped(db,ctx,tx=>tx.enqueue('scan',{},'last-attempt',1));
  const job=await scoped(db,ctx,tx=>tx.claim('worker',1000));assert.ok(job);
  await assert.rejects(scoped(db,at(1000),tx=>tx.acknowledge(job)),code('stale_lease'));
  await assert.rejects(scoped(db,at(1000),tx=>tx.fail(job,'fixture_error')),code('stale_lease'));
  assert.equal(await scoped(db,at(1000),tx=>tx.claim('next-worker')),null);
  await raw(db,ctx,async q=>{const row=(await q.query<{state:string;last_error:string;lease_owner:null;lease_until:null;generation:number}>('SELECT * FROM public.evidence_outbox')).rows[0]!;assert.equal(row.state,'dead');assert.equal(row.last_error,'attempts_exhausted');assert.equal(row.lease_owner,null);assert.equal(row.lease_until,null);assert.equal(row.generation,1);});
});

test('failed jobs respect retry delay and max attempts, and validate bounded error codes',async t=>{
  const {db}=await setup(t);await scoped(db,ctx,tx=>tx.enqueue('scan',{},'retry',2));
  const one=await scoped(db,ctx,tx=>tx.claim('worker',10000));assert.ok(one);
  await assert.rejects(scoped(db,ctx,tx=>tx.fail(one,'raw provider secret: fixture')),code('invalid_error'));
  await scoped(db,ctx,tx=>tx.fail(one,'fixture_retry',1000));
  assert.equal(await scoped(db,at(999),tx=>tx.claim('worker')),null);
  const two=await scoped(db,at(1000),tx=>tx.claim('worker'));assert.ok(two);assert.equal(two.generation,2);
  await scoped(db,at(1000),tx=>tx.fail(two,'fixture_terminal',0));
  assert.equal(await scoped(db,at(2000),tx=>tx.claim('worker')),null);
  await raw(db,ctx,async q=>assert.equal((await q.query<{state:string}>('SELECT state FROM public.evidence_outbox')).rows[0]!.state,'dead'));
});

test('transaction scope is captured before awaits, injection strings are data, raw driver is inaccessible and escaped UoWs close',async t=>{
  const {db,pg}=await setup(t);const mutable=structuredClone(ctx);let escaped:UnitOfWork|undefined;
  const pending=scoped(db,mutable,async tx=>{escaped=tx;assert.equal('q' in tx,false);assert.equal('ctx' in tx,false);await tx.put('evidence',"id'; RESET ROLE; --",0,{fixture:true});});
  Object.assign(mutable,{tenantId:'mutated'});Object.assign(mutable.actor,{id:'mutated-actor'});await pending;
  const original=await scoped(db,ctx,tx=>tx.get('evidence',"id'; RESET ROLE; --"));assert.equal(original?.actorId,ctx.actor.id);
  await assert.rejects(escaped!.get('evidence','anything'),code('transaction_aborted'));
  const injected={...ctx,tenantId:"tenant'; RESET ROLE; --"};await scoped(db,injected,tx=>tx.put('evidence','own',0,{}));
  assert.equal(await scoped(db,ctx,tx=>tx.get('evidence','own')),null);
  assert.equal((await pg.query<{name:string}>('SELECT current_user AS name')).rows[0]!.name,'evidence_test_login');
});

test('authenticated migration/superuser, owner, bypass and privileged membership connections are rejected',async t=>{
  const {db,pg}=await setup(t,false);
  await assert.rejects(scoped(db,ctx,tx=>tx.get('evidence','x')),code('unsafe_database_role'));
  // SET ROLE must not make a privileged session_user acceptable.
  await assert.rejects(db.transaction(async q=>{await q.query('SET LOCAL ROLE evidence_runtime');await assertRuntimeConnection(q);}),code('unsafe_database_role'));
  await pg.exec('CREATE ROLE fixture_owner NOLOGIN; GRANT evidence_runtime TO fixture_owner; GRANT fixture_owner TO evidence_test_login; ALTER TABLE public.evidence_record OWNER TO fixture_owner; SET SESSION AUTHORIZATION evidence_test_login;');
  await assert.rejects(scoped(db,ctx,tx=>tx.get('evidence','x')),code('unsafe_database_role'));
  await pg.exec('SET SESSION AUTHORIZATION postgres; ALTER TABLE public.evidence_record OWNER TO postgres; REVOKE fixture_owner FROM evidence_test_login; CREATE ROLE fixture_bypass NOLOGIN BYPASSRLS; GRANT fixture_bypass TO evidence_test_login; SET SESSION AUTHORIZATION evidence_test_login;');
  await assert.rejects(scoped(db,ctx,tx=>tx.get('evidence','x')),code('unsafe_database_role'));
  await pg.exec('SET SESSION AUTHORIZATION postgres; REVOKE fixture_bypass FROM evidence_test_login; ALTER ROLE evidence_test_login BYPASSRLS; SET SESSION AUTHORIZATION evidence_test_login;');
  await assert.rejects(scoped(db,ctx,tx=>tx.get('evidence','x')),code('unsafe_database_role'));
});

test('metadata, audit and outbox survive a PGlite filesystem restart',async t=>{
  const root=await mkdtemp(join(tmpdir(),'evidence-durable-fixture-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const pg=new PGlite(root);await pg.exec(migration);await pg.exec('CREATE ROLE evidence_test_login LOGIN NOINHERIT; GRANT evidence_runtime TO evidence_test_login; SET SESSION AUTHORIZATION evidence_test_login;');
  const db=adapter(pg);await scoped(db,ctx,async tx=>{await tx.put('evidence','durable',0,{fixture:'persisted'});await tx.enqueue('scan',{},'durable-job');});await db.close();
  const restarted=new PGlite(root);t.after(()=>restarted.close());await restarted.exec('SET SESSION AUTHORIZATION evidence_test_login');
  await scoped(adapter(restarted),ctx,async tx=>{assert.deepEqual((await tx.get('evidence','durable'))?.value,{fixture:'persisted'});assert.ok(verifyAudit(await tx.audits()));assert.equal((await tx.claim('worker'))?.id,'durable-job');});
});

test('job handles bind tenant/project even when IDs, owners and generations coincide',async t=>{
  const {db}=await setup(t);const foreign={...ctx,projectId:'other-project'};
  let own:LeasedJob|null=null;let other:LeasedJob|null=null;
  for(const scope of [ctx,foreign]){
    await scoped(db,scope,tx=>tx.enqueue('scan',{},'same-id'));
    const job=await scoped(db,scope,tx=>tx.claim('same-worker'));
    if(scope===ctx)own=job;else other=job;
  }
  assert.ok(own&&other);assert.equal(own.generation,other.generation);
  await assert.rejects(scoped(db,foreign,tx=>tx.acknowledge(own!)),code('scope_denied'));
  await assert.rejects(scoped(db,ctx,tx=>tx.fail(other!,'fixture_error')),code('scope_denied'));
  await scoped(db,ctx,tx=>tx.acknowledge(own!));await scoped(db,foreign,tx=>tx.acknowledge(other!));
});

test('put captures caller JSON and stores an actual evidence engine snapshot',async t=>{
  const {db}=await setup(t);const payload={fixture:'original'};
  const pending=scoped(db,ctx,async tx=>{const put=tx.put('evidence','captured',0,payload);payload.fixture='mutated';await put;});await pending;
  assert.deepEqual((await scoped(db,ctx,tx=>tx.get('evidence','captured')))?.value,{fixture:'original'});
  const {createEvidenceState,acquireEvidence,assertEvidenceState}=await import('../src/index.ts');
  const state=acquireEvidence(createEvidenceState(ctx),ctx,{id:'original',acquisitionId:'fixture-acquisition',bytes:Buffer.from('fixture'),mediaType:'text/plain',storageVersionRef:'fixture-object',sourceFamilyId:null,capturedAt:ctx.now,originalLanguage:'und',allowedPurposes:[ctx.purpose],supersedes:null});
  await scoped(db,ctx,tx=>tx.put('evidence-state','fixture',0,state));
  const loaded=await scoped(db,ctx,tx=>tx.get<typeof state>('evidence-state','fixture'));assert.ok(loaded);assertEvidenceState(loaded.value);assert.deepEqual(loaded.value,state);
});

test('unawaited transaction work cannot run SQL after commit or escape into the next scope',async t=>{
  const {db}=await setup(t);let pending:Promise<unknown>|undefined;
  await assert.rejects(scoped(db,ctx,async tx=>{pending=tx.put('evidence','unawaited',0,{});void pending.catch(()=>{});}),code('transaction_aborted'));
  await assert.rejects(pending!,code('transaction_aborted'));
  assert.equal(await scoped(db,ctx,tx=>tx.get('evidence','unawaited')),null);
});
