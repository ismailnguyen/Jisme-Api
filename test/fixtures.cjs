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

module.exports={fixture,registrationFixture,config,b64,hash};
