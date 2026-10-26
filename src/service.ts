import {authenticate,authorize,type Identity} from './identity-sdk.ts';
import {digest,hashBytes,invariant,requireScope,type Context} from './contracts.ts';
import {scoped,type Database} from './database.ts';
import {PrivateObjectStore,type ObjectReceipt} from './objects.ts';
import {acquireEvidence,createEvidenceState,requireEvidenceUsable,type EvidenceState,type EvidenceRef} from './index.ts';

export type EvidenceRequest=Readonly<{token:string;purpose:string;requestId:string}>;
export type AcquireCommand=Readonly<{id:string;acquisitionId:string;bytes:Uint8Array;mediaType:string;capturedAt:string;originalLanguage:string;supersedes:EvidenceRef|null;expectedRevision:number;idempotencyKey:string}>;
export type ObjectBinding=Readonly<{evidence:EvidenceRef;receipt:ObjectReceipt}>;
export type EvidenceAggregate=Readonly<{domain:EvidenceState;objects:readonly ObjectBinding[]}>;
export interface EvidenceServiceOptions {database:Database;objects:PrivateObjectStore;identities:()=>Promise<readonly Identity[]>;now:()=>string;}
const KIND='evidence.aggregate',ID='project';
/** Initial checkpoint: authentication/acquisition composition; scan worker and orphan reconciliation follow. */
export class EvidenceService {
 #options:EvidenceServiceOptions;
 constructor(options:EvidenceServiceOptions){this.#options=options;}
 async #context(request:EvidenceRequest):Promise<Context>{
  const identity=authenticate(request.token,await this.#options.identities());
  return {tenantId:identity.tenantId,projectId:identity.projectId,actor:identity.actor,purpose:request.purpose,requestId:request.requestId,now:this.#options.now()};
 }
 async acquire(request:EvidenceRequest,command:AcquireCommand):Promise<{ref:EvidenceRef;revision:number}>{
  const input={...structuredClone(command),bytes:new Uint8Array(command.bytes)};
  const ctx=await this.#context(request);authorize(ctx,'investigate');
  return scoped(this.#options.database,ctx,tx=>tx.idempotent(command.idempotencyKey,{...input,bytes:hashBytes(input.bytes)},async()=>{
   const existing=await tx.get<EvidenceAggregate>(KIND,ID);
   invariant((existing?.revision??0)===input.expectedRevision,'revision_conflict','Evidence aggregate changed');
   const aggregate=existing?.value??{domain:createEvidenceState(ctx),objects:[]};
   const receipt=await this.#options.objects.put(ctx,input.bytes);
   const domain=acquireEvidence(aggregate.domain,ctx,{id:input.id,acquisitionId:input.acquisitionId,bytes:input.bytes,mediaType:input.mediaType,storageVersionRef:digest(receipt),sourceFamilyId:null,capturedAt:input.capturedAt,originalLanguage:input.originalLanguage,allowedPurposes:[ctx.purpose],supersedes:input.supersedes});
   const ref=domain.versions.at(-1)!.ref;
   const next=await tx.put(KIND,ID,input.expectedRevision,{domain,objects:[...aggregate.objects,{evidence:ref,receipt}]});
   await tx.enqueue('evidence.scan',{evidence:ref,sha256:hashBytes(input.bytes)},`scan:${digest(ref)}`);
   return {ref,revision:next.revision};
  }));
 }
 async read(request:EvidenceRequest,ref:EvidenceRef):Promise<Uint8Array>{
  const ctx=await this.#context(request);authorize(ctx,'read',ref);requireScope(ctx,ref);
  return scoped(this.#options.database,ctx,async tx=>{
   const aggregate=(await tx.get<EvidenceAggregate>(KIND,ID))?.value;invariant(aggregate,'not_found','Evidence aggregate missing');
   requireEvidenceUsable(aggregate.domain,ctx,ref);
   const binding=aggregate.objects.find(b=>digest(b.evidence)===digest(ref));invariant(binding,'not_found','Object receipt missing');
   return this.#options.objects.get(ctx,binding.receipt);
  });
 }
}
