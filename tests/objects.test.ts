import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm,readdir,rename,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {DomainError} from '../src/contracts.ts';
import {PrivateObjectStore} from '../src/objects.ts';
const scope={tenantId:'tenant-fixture',projectId:'project-fixture'};
const errorCode=(code:string)=>(error:unknown)=>error instanceof DomainError && error.code===code;
async function fixture(t:{after:(fn:()=>Promise<void>)=>void}){
  const root=await mkdtemp(join(tmpdir(),'evidence-fixture-')); t.after(()=>rm(root,{recursive:true,force:true}));
  const key=randomBytes(32); return {root,key,store:new PrivateObjectStore(root,key,'fixture-key-1')};
}

test('AES-GCM storage round trips exact binary and deduplicates without replacing ciphertext',async t=>{
  const {root,store}=await fixture(t); const bytes=Buffer.from([0,255,13,10,42]);
  const receipt=await store.put(scope,bytes); assert.equal(receipt.plaintextHash,createHash('sha256').update(bytes).digest('hex'));
  assert.deepEqual(Buffer.from(await store.get(scope,receipt)),bytes);
  const path=join(root,receipt.key); const before=await readFile(path);
  assert.deepEqual(await store.put(scope,bytes),receipt); assert.deepEqual(await readFile(path),before);
  assert.deepEqual(await readdir(dirname(path)),[receipt.plaintextHash]);
  const empty=await store.put(scope,new Uint8Array()); assert.equal((await store.get(scope,empty)).length,0);
});

test('put snapshots caller bytes before asynchronous filesystem work',async t=>{
  const {store}=await fixture(t); const bytes=Buffer.from('original fixture'); const expected=Buffer.from(bytes);
  const pending=store.put(scope,bytes); bytes.fill(0); const receipt=await pending;
  assert.deepEqual(Buffer.from(await store.get(scope,receipt)),expected);
});

test('scope, project, receipt size, path traversal and unavailable keys fail closed',async t=>{
  const {root,store}=await fixture(t); const bytes=Buffer.from('fixture'); const receipt=await store.put(scope,bytes);
  for(const other of [{...scope,tenantId:'other-tenant'},{...scope,projectId:'other-project'}]){
    await assert.rejects(store.get(other,receipt),errorCode('object_scope_denied'));
    const isolated=await store.put(other,bytes); assert.notEqual(isolated.key,receipt.key);
  }
  await assert.rejects(store.get(scope,{...receipt,key:'../../fixture'}),errorCode('object_scope_denied'));
  await assert.rejects(store.get(scope,{...receipt,size:receipt.size+1}),errorCode('integrity_failure'));
  await assert.rejects(store.get(scope,{...receipt,keyVersion:'missing'}),errorCode('key_unavailable'));
  await assert.rejects(new PrivateObjectStore(root,randomBytes(32),'fixture-key-1').get(scope,receipt));
});

for(const field of ['data','tag','iv','keyVersion','v'] as const)test(`encrypted ${field} tampering is rejected`,async t=>{
  const {root,store}=await fixture(t); const receipt=await store.put(scope,Buffer.from('synthetic fixture'));
  const path=join(root,receipt.key); const envelope=JSON.parse(await readFile(path,'utf8')) as Record<string,unknown>;
  if(field==='v')envelope[field]=2;
  else if(field==='keyVersion')envelope[field]='other';
  else {const bytes=Buffer.from(envelope[field] as string,'base64');bytes[0]=bytes[0]!^1;envelope[field]=bytes.toString('base64');}
  await writeFile(path,JSON.stringify(envelope)); await assert.rejects(store.get(scope,receipt));
  await assert.rejects(store.put(scope,Buffer.from('synthetic fixture')));
});

test('symlinked object files and tenant directories are rejected',async t=>{
  const {root,store}=await fixture(t); const receipt=await store.put(scope,Buffer.from('fixture'));
  const path=join(root,receipt.key); await rename(path,path+'.saved'); await symlink(path+'.saved',path);
  await assert.rejects(store.get(scope,receipt),errorCode('unsafe_storage'));
  await rm(path); await rename(path+'.saved',path);
  const dir=dirname(path); await rename(dir,dir+'.saved'); await symlink(dir+'.saved',dir,'dir');
  await assert.rejects(store.get(scope,receipt),errorCode('unsafe_storage'));
  await assert.rejects(store.put(scope,Buffer.from('fixture')),errorCode('unsafe_storage'));
});
