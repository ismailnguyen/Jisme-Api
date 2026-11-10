'use strict';
const {generateKeyPairSync,createHash,sign,randomBytes}=require('node:crypto');
const {isoCBOR}=require('@simplewebauthn/server/helpers');
const config={origin:'https://vault.example.invalid',rpID:'vault.example.invalid'};
const b64=x=>Buffer.from(x).toString('base64url');
const hash=x=>createHash('sha256').update(x).digest();
function fixture({challenge=b64(randomBytes(32)),origin=config.origin,rpID=config.rpID,flags=5,counter=1,type='webauthn.get',crossOrigin=false}={}){
 const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const jwk=keys.publicKey.export({format:'jwk'});
 const publicKey=isoCBOR.encode(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
 const id=randomBytes(32);const count=Buffer.alloc(4);count.writeUInt32BE(counter);
 const authenticatorData=Buffer.concat([hash(rpID),Buffer.from([flags]),count]);
 const clientDataJSON=Buffer.from(JSON.stringify({type,challenge,origin,crossOrigin}));
 const signature=sign('sha256',Buffer.concat([authenticatorData,hash(clientDataJSON)]),keys.privateKey);
 return {challenge,credential:{id:b64(id),publicKey:b64(publicKey),counter:0,validated:true,userId:'owner'},userId:'owner',response:{id:b64(id),rawId:b64(id),type:'public-key',clientExtensionResults:{},response:{clientDataJSON:b64(clientDataJSON),authenticatorData:b64(authenticatorData),signature:b64(signature),userHandle:b64(Buffer.from('owner'))}},id,publicKey,authenticatorData};
}
function registrationFixture(opts={}){
 const f=fixture({...opts,type:'webauthn.create'});
 const length=Buffer.alloc(2);length.writeUInt16BE(f.id.length);
 const authData=Buffer.concat([f.authenticatorData.subarray(0,32),Buffer.from([(opts.flags??5)|64]),f.authenticatorData.subarray(33),Buffer.alloc(16),length,f.id,Buffer.from(f.publicKey)]);
 f.response.response={clientDataJSON:f.response.response.clientDataJSON,attestationObject:b64(isoCBOR.encode(new Map([['fmt','none'],['attStmt',new Map()],['authData',authData]])))};
 return f;
}

// Software authenticator with a persistent P-256 key: one registration, then
// any number of signed assertions (counter, flags, origin, rpID controllable).
function authenticator({rpID=config.rpID,origin=config.origin}={}){
 const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const jwk=keys.publicKey.export({format:'jwk'});
 const cose=isoCBOR.encode(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
 const rawId=randomBytes(32);const id=b64(rawId);
 const authData=(rp,flags,counter,extra=Buffer.alloc(0))=>{const c=Buffer.alloc(4);c.writeUInt32BE(counter);return Buffer.concat([hash(rp),Buffer.from([flags]),c,extra]);};
 const clientData=(type,challenge,o)=>Buffer.from(JSON.stringify({type,challenge,origin:o,crossOrigin:false}));
 return {id,
  register(challenge,{flags=5,origin:o=origin,rpID:r=rpID,transports=['internal'],extensions={}}={}){
   const len=Buffer.alloc(2);len.writeUInt16BE(rawId.length);
   const ad=authData(r,flags|64,0,Buffer.concat([Buffer.alloc(16),len,rawId,Buffer.from(cose)]));
   return {id,rawId:id,type:'public-key',clientExtensionResults:extensions,response:{clientDataJSON:b64(clientData('webauthn.create',challenge,o)),attestationObject:b64(isoCBOR.encode(new Map([['fmt','none'],['attStmt',new Map()],['authData',ad]]))),transports}};
  },
  assert(challenge,{counter=1,flags=5,origin:o=origin,rpID:r=rpID,userHandle,extensions={},tamper=false}={}){
   const ad=authData(r,flags,counter);const cd=clientData('webauthn.get',challenge,o);
   const sig=sign('sha256',Buffer.concat([ad,hash(cd)]),keys.privateKey);if(tamper)sig[sig.length-1]^=1;
   return {id,rawId:id,type:'public-key',clientExtensionResults:extensions,response:{clientDataJSON:b64(cd),authenticatorData:b64(ad),signature:b64(sig),...(userHandle?{userHandle}:{})}};
  }};
}

module.exports={fixture,registrationFixture,authenticator,config,b64,hash};
