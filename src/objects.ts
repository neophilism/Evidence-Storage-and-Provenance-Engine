import { createCipheriv,createDecipheriv,randomBytes } from 'node:crypto';
import { mkdir,open,readFile,lstat,link,unlink } from 'node:fs/promises';
import { resolve,join } from 'node:path';
import type { Scope } from './contracts.ts';
import { canonical,digest,hashBytes,invariant } from './contracts.ts';
export interface ObjectReceipt {key:string;plaintextHash:string;size:number;keyVersion:string;}
export class PrivateObjectStore {
 readonly root:string;readonly key:Uint8Array;readonly keyVersion:string;
 constructor(root:string,key:Uint8Array,keyVersion:string){invariant(key.length===32,'invalid_key','AES256 requires32bytes');this.root=resolve(root);this.key=new Uint8Array(key);this.keyVersion=keyVersion;}
 async put(scope:Scope,bytes:Uint8Array):Promise<ObjectReceipt>{
 invariant(bytes.length<=25*1024*1024,'object_too_large','Maximum object size is25MiB');
 // Snapshot caller-owned values before the first await so receipts bind the encrypted bytes.
 scope={tenantId:scope.tenantId,projectId:scope.projectId};bytes=new Uint8Array(bytes);
 const scopeHash=digest(scope),plaintextHash=hashBytes(bytes),key=`${scopeHash}/${plaintextHash}`;
 const dir=join(this.root,scopeHash);await mkdir(dir,{recursive:true,mode:0o700});invariant(!(await lstat(dir)).isSymbolicLink(),'unsafe_storage','Symlinked object directories forbidden');
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,iv);cipher.setAAD(Buffer.from(canonical({scope,keyVersion:this.keyVersion,plaintextHash})));
 const encrypted=Buffer.concat([cipher.update(bytes),cipher.final()]);const envelope=Buffer.from(JSON.stringify({v:1,keyVersion:this.keyVersion,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:encrypted.toString('base64')}));
 const temp=join(dir,`.pending-${randomBytes(16).toString('hex')}`);const f=await open(temp,'wx',0o600);
 try{try{await f.writeFile(envelope);await f.sync();}finally{await f.close();}
  try{await link(temp,join(this.root,key));}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;await this.get(scope,{key,plaintextHash,size:bytes.length,keyVersion:this.keyVersion});}
 }finally{await unlink(temp);}

 return {key,plaintextHash,size:bytes.length,keyVersion:this.keyVersion};
 }
 async get(scope:Scope,receipt:ObjectReceipt):Promise<Uint8Array>{
 scope={tenantId:scope.tenantId,projectId:scope.projectId};receipt={...receipt};
 invariant(/^[a-f0-9]{64}\/[a-f0-9]{64}$/.test(receipt.key)&&receipt.key===`${digest(scope)}/${receipt.plaintextHash}`,'object_scope_denied','Invalid scoped object reference');
 invariant(receipt.keyVersion===this.keyVersion,'key_unavailable','Object key version unavailable');
 const dir=join(this.root,digest(scope));invariant(!(await lstat(dir)).isSymbolicLink(),'unsafe_storage','Symlinked object directories forbidden');
 const path=join(this.root,receipt.key);invariant(!(await lstat(path)).isSymbolicLink(),'unsafe_storage','Symlinked objects forbidden');
 const envelope=JSON.parse(await readFile(path,'utf8')) as {v:number;keyVersion:string;iv:string;tag:string;data:string};
 invariant(envelope.v===1&&envelope.keyVersion===this.keyVersion,'invalid_object','Unsupported encrypted envelope');
 const decipher=createDecipheriv('aes-256-gcm',this.key,Buffer.from(envelope.iv,'base64'));decipher.setAAD(Buffer.from(canonical({scope,keyVersion:this.keyVersion,plaintextHash:receipt.plaintextHash})));decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
 const bytes=Buffer.concat([decipher.update(Buffer.from(envelope.data,'base64')),decipher.final()]);invariant(hashBytes(bytes)===receipt.plaintextHash&&bytes.length===receipt.size,'integrity_failure','Stored bytes do not match receipt');return bytes;
 }
}
