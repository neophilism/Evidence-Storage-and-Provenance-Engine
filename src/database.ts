import { Pool } from 'pg';
import type { Context, Json, AuditEvent, Revision } from './contracts.ts';
import { invariant, digest, newId, nonempty, validTime } from './contracts.ts';
export interface Query { query<T=Record<string,unknown>>(sql:string, values?:unknown[]): Promise<{rows:T[]}> }
export interface Database { transaction<T>(fn:(q:Query)=>Promise<T>):Promise<T>; close():Promise<void>; }
export function postgresDatabase(url:string):Database {
 const pool=new Pool({connectionString:url, max:10, connectionTimeoutMillis:5000, statement_timeout:10000});
 return { async transaction<T>(fn:(q:Query)=>Promise<T>):Promise<T>{
   const c=await pool.connect();
   try {await c.query('BEGIN'); const result=await fn({query:async<T>(sql:string,values?:unknown[])=>({rows:(await c.query(sql,values)).rows as T[]})}); await c.query('COMMIT'); return result;}
   catch(e){await c.query('ROLLBACK');throw e;} finally{c.release();}
 }, close:()=>pool.end() };
}
export async function scoped<T>(db:Database,ctx:Context,fn:(tx:UnitOfWork)=>Promise<T>):Promise<T>{
 nonempty(ctx.tenantId,'tenant',128);nonempty(ctx.projectId,'project',128);nonempty(ctx.actor.id,'actor',128);validTime(ctx.now);
 return db.transaction(async q=>{
  await q.query("SELECT set_config('evidence.tenant_id',$1,true), set_config('evidence.project_id',$2,true)",[ctx.tenantId,ctx.projectId]);
  await q.query('SET LOCAL ROLE evidence_runtime');
  return fn(new UnitOfWork(q,ctx));
 });
}
export class UnitOfWork {
 readonly q:Query; readonly ctx:Context;
 constructor(q:Query,ctx:Context){this.q=q;this.ctx=ctx;}
 async ensureProject():Promise<void>{await this.q.query('INSERT INTO evidence_project(tenant_id,project_id) VALUES($1,$2) ON CONFLICT DO NOTHING',this.scope());}
 private scope():[string,string]{return [this.ctx.tenantId,this.ctx.projectId];}
 async lock():Promise<void>{await this.ensureProject();await this.q.query('SELECT project_id FROM evidence_project WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE',this.scope());}
 async get<T>(kind:string,id:string,revision?:number):Promise<Revision<T>|null>{
 const rows=await this.q.query<{revision:number;value:T;created_at:Date|string;actor_id:string}>(revision===undefined?
  'SELECT r.* FROM evidence_record r JOIN evidence_head h USING(tenant_id,project_id,kind,id,revision) WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.kind=$3 AND r.id=$4':
  'SELECT * FROM evidence_record WHERE tenant_id=$1 AND project_id=$2 AND kind=$3 AND id=$4 AND revision=$5',revision===undefined?[...this.scope(),kind,id]:[...this.scope(),kind,id,revision]);
 const r=rows.rows[0];return r?{tenantId:this.ctx.tenantId,projectId:this.ctx.projectId,id,kind,revision:r.revision,value:r.value,createdAt:new Date(r.created_at).toISOString(),actorId:r.actor_id}:null;
 }
 async list<T>(kind:string,limit=100,after=''):Promise<Revision<T>[]>{
 invariant(Number.isInteger(limit)&&limit>0&&limit<=500,'invalid_limit','Limit must be1-500');
 const r=await this.q.query<{id:string;revision:number;value:T;created_at:Date|string;actor_id:string}>('SELECT r.* FROM evidence_record r JOIN evidence_head h USING(tenant_id,project_id,kind,id,revision) WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.kind=$3 AND r.id>$4 ORDER BY r.id LIMIT $5',[...this.scope(),kind,after,limit]);
 return r.rows.map(row=>({tenantId:this.ctx.tenantId,projectId:this.ctx.projectId,kind,id:row.id,revision:row.revision,value:row.value,createdAt:new Date(row.created_at).toISOString(),actorId:row.actor_id}));
 }
 async put<T>(kind:string,id:string,expectedRevision:number,value:T):Promise<Revision<T>>{
 nonempty(kind,'kind',64);nonempty(id,'id',128);digest(value);await this.lock();
 const current=await this.get<T>(kind,id);invariant((current?.revision??0)===expectedRevision,'revision_conflict','Resource revision changed');
 const revision=expectedRevision+1;
 await this.q.query('INSERT INTO evidence_record(tenant_id,project_id,kind,id,revision,value,created_at,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[...this.scope(),kind,id,revision,JSON.stringify(value),this.ctx.now,this.ctx.actor.id]);
 await this.q.query('INSERT INTO evidence_head(tenant_id,project_id,kind,id,revision) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,project_id,kind,id) DO UPDATE SET revision=EXCLUDED.revision',[...this.scope(),kind,id,revision]);
 await this.audit('record.revised',{kind,id,revision,valueHash:digest(value)});
 return {tenantId:this.ctx.tenantId,projectId:this.ctx.projectId,id,kind,revision,value,createdAt:this.ctx.now,actorId:this.ctx.actor.id};
 }
 async audit(type:string,payload:Json):Promise<AuditEvent>{
 await this.lock();const r=await this.q.query<{audit_sequence:string|number;audit_hash:string}>('SELECT audit_sequence,audit_hash FROM evidence_project WHERE tenant_id=$1 AND project_id=$2',this.scope());
 const head=r.rows[0]!;const base={tenantId:this.ctx.tenantId,projectId:this.ctx.projectId,id:newId(),sequence:Number(head.audit_sequence)+1,type,actorId:this.ctx.actor.id,at:new Date(this.ctx.now).toISOString(),requestId:this.ctx.requestId,payload,previousHash:head.audit_hash};const hash=digest(base);
 await this.q.query('INSERT INTO evidence_audit(tenant_id,project_id,sequence,id,type,actor_id,at,request_id,payload,previous_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[...this.scope(),base.sequence,base.id,type,base.actorId,base.at,base.requestId,JSON.stringify(payload),base.previousHash,hash]);
 await this.q.query('UPDATE evidence_project SET audit_sequence=$3,audit_hash=$4 WHERE tenant_id=$1 AND project_id=$2',[...this.scope(),base.sequence,hash]);return {...base,hash};
 }
 async audits():Promise<AuditEvent[]>{const r=await this.q.query<{id:string;sequence:string|number;type:string;actor_id:string;at:string|Date;request_id:string;payload:Json;previous_hash:string;hash:string}>('SELECT * FROM evidence_audit WHERE tenant_id=$1 AND project_id=$2 ORDER BY sequence',this.scope());return r.rows.map(r=>({tenantId:this.ctx.tenantId,projectId:this.ctx.projectId,id:r.id,sequence:Number(r.sequence),type:r.type,actorId:r.actor_id,at:new Date(r.at).toISOString(),requestId:r.request_id,payload:r.payload,previousHash:r.previous_hash,hash:r.hash}));}
 async idempotent<T extends Json>(key:string,input:unknown,fn:()=>Promise<T>):Promise<T>{
 nonempty(key,'idempotency key',200);await this.lock();const fingerprint=digest(input);
 const r=await this.q.query<{fingerprint:string;result:T}>('SELECT fingerprint,result FROM evidence_idempotency WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND key=$4',[...this.scope(),this.ctx.actor.id,key]);
 if(r.rows[0]){invariant(r.rows[0].fingerprint===fingerprint,'idempotency_conflict','Key already used for different command');return r.rows[0].result;}
 const result=await fn();await this.q.query('INSERT INTO evidence_idempotency(tenant_id,project_id,actor_id,key,fingerprint,result) VALUES($1,$2,$3,$4,$5,$6)',[...this.scope(),this.ctx.actor.id,key,fingerprint,JSON.stringify(result)]);return result;
 }
 async enqueue(topic:string,payload:Json,id=newId()):Promise<string>{await this.ensureProject();await this.q.query('INSERT INTO evidence_outbox(tenant_id,project_id,id,topic,payload,available_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',[...this.scope(),id,topic,JSON.stringify(payload),this.ctx.now]);return id;}
 async claim(worker:string,leaseMs=30000):Promise<LeasedJob|null>{
 await this.q.query("UPDATE evidence_outbox SET state='dead',lease_until=NULL,last_error='attempts_exhausted' WHERE tenant_id=$1 AND project_id=$2 AND state='leased' AND lease_until<=$3 AND attempts>=max_attempts",[...this.scope(),this.ctx.now]);
 nonempty(worker,'worker',128);invariant(leaseMs>=1000&&leaseMs<=300000,'invalid_lease','Lease must be1-300seconds');
 const r=await this.q.query<JobRow>(`WITH next AS (SELECT id FROM evidence_outbox WHERE tenant_id=$1 AND project_id=$2 AND attempts<max_attempts AND ((state='pending' AND available_at<=$3) OR (state='leased' AND lease_until<=$3)) ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE evidence_outbox SET state='leased',generation=generation+1,attempts=attempts+1,lease_owner=$4,lease_until=$5 WHERE tenant_id=$1 AND project_id=$2 AND id IN(SELECT id FROM next) RETURNING *`,[...this.scope(),this.ctx.now,worker,new Date(validTime(this.ctx.now)+leaseMs).toISOString()]);
 const j=r.rows[0];return j?{id:j.id,topic:j.topic,payload:j.payload,generation:j.generation,attempts:j.attempts,leaseOwner:worker}:null;
 }
 async acknowledge(job:LeasedJob):Promise<void>{const r=await this.q.query(`UPDATE evidence_outbox SET state='completed',lease_until=NULL WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND state='leased' AND generation=$4 AND lease_owner=$5 AND lease_until>$6 RETURNING id`,[...this.scope(),job.id,job.generation,job.leaseOwner,this.ctx.now]);invariant(r.rows.length===1,'stale_lease','Lease expired or superseded');}
 async fail(job:LeasedJob,code:string,retryMs=1000):Promise<void>{
 invariant(/^[a-z0-9_]{1,64}$/.test(code),'invalid_error','Use a bounded error code, not raw provider text');invariant(Number.isInteger(retryMs)&&retryMs>=0&&retryMs<=3600000,'invalid_retry','Retry must be0-3600seconds');
 const r=await this.q.query(`UPDATE evidence_outbox SET state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'pending' END,lease_until=NULL,last_error=$6,available_at=$7 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND state='leased' AND generation=$4 AND lease_owner=$5 AND lease_until>$8 RETURNING id`,[...this.scope(),job.id,job.generation,job.leaseOwner,code,new Date(validTime(this.ctx.now)+retryMs).toISOString(),this.ctx.now]);invariant(r.rows.length===1,'stale_lease','Lease expired or superseded');
 }
}
interface JobRow {id:string;topic:string;payload:Json;generation:number;attempts:number;}
export interface LeasedJob extends JobRow {leaseOwner:string;}
export function verifyAudit(events:AuditEvent[]):boolean {let previous='';let sequence=0;for(const e of events){const {hash,...base}=e;if(e.sequence!==++sequence||e.previousHash!==previous||digest(base)!==hash)return false;previous=hash;}return true;}
