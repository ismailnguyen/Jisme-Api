'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,createHash,sign,randomBytes}=require('node:crypto');
const {isoCBOR}=require('@simplewebauthn/server/helpers');
const fs=require('node:fs');
const path=require('node:path');
const mod=path.join(__dirname,'../services/webauthnVerifier.js');
const api=()=>{assert.ok(fs.existsSync(mod),'standalone verifier is missing');return require(mod);};
const {fixture,registrationFixture,config,b64,hash}=require('./fixtures.cjs');
test('real signed ES256 assertion verifies with explicit config',async()=>{
 const f=fixture(); const result=await api().createVerifier(config).authentication(f);
 assert.equal(result.newCounter,1);
});
module.exports={fixture,config,b64,hash};
for(const [name,change] of [
 ['signature',f=>{f.response.response.signature=b64(Buffer.alloc(72));}],
 ['challenge',f=>{f.challenge=b64(randomBytes(32));}],
 ['origin',f=>Object.assign(f,fixture({origin:'https://evil.example.invalid'}))],
 ['rpID',f=>Object.assign(f,fixture({rpID:'evil.example.invalid'}))],
 ['UV',f=>Object.assign(f,fixture({flags:1}))],
 ['UP',f=>Object.assign(f,fixture({flags:4}))],
 ['missing proof',f=>{delete f.response.response.signature;}],
 ['wrong user',f=>{f.userId='another';}],
 ['wrong credential ID',f=>{f.credential.id=b64(randomBytes(32));}],
 ['wrong userHandle',f=>{f.response.response.userHandle=b64(Buffer.from('another'));}],
 ['legacy key',f=>{delete f.credential.validated;}],
 ['counter rollback',f=>{f.credential.counter=1;}],
 ['PRF output',f=>{f.response.clientExtensionResults={prf:{results:{first:'secret'}}};}],
 ['nested PRF output',f=>{f.response.extra={prfOutput:'secret'};}],
 ['cross origin',f=>Object.assign(f,fixture({crossOrigin:true}))],
]) test('assertion rejects '+name,async()=>{
 const f=fixture();change(f);await assert.rejects(api().createVerifier(config).authentication(f));
});
for(const invalid of [{},{origin:config.origin},{...config,origin:'http://vault.example.invalid'},{...config,origin:config.origin+'/'},{...config,rpID:'evil.invalid'},{...config,rpID:'https://vault.example.invalid'}])
 test('config refuses '+JSON.stringify(invalid),()=>assert.throws(()=>api().createVerifier(invalid)));
test('enrollment validates fresh ceremony and yields a stored public key',async()=>{
 const f=registrationFixture();const result=await api().createVerifier(config).registration(f);
 assert.equal(result.id,f.response.id);assert.equal(result.publicKey,b64(f.publicKey));assert.equal(result.validated,true);
});
module.exports.registrationFixture=registrationFixture;
test('truthy client-supplied validation marker is not trusted',async()=>{
 const f=fixture();f.credential.validated='yes';await assert.rejects(api().createVerifier(config).authentication(f));
});
for(const [name,options,change] of [
 ['challenge',{},f=>{f.challenge='wrong';}],['origin',{origin:'https://evil.invalid'}],['rpID',{rpID:'evil.invalid'}],['UV',{flags:1}],['UP',{flags:4}],['crossOrigin',{crossOrigin:true}],['missing attestation',{},f=>{delete f.response.response.attestationObject;}],['PRF',{},f=>{f.response.clientExtensionResults={prf:{results:{first:'secret'}}};}]
]) test('enrollment rejects '+name,async()=>{
 const f=registrationFixture(options);change?.(f);await assert.rejects(api().createVerifier(config).registration(f));
});
test('zero-counter authenticators still require valid signatures',async()=>{
 const f=fixture({counter:0});assert.equal((await api().createVerifier(config).authentication(f)).newCounter,0);
 f.response.response.signature='AA';await assert.rejects(api().createVerifier(config).authentication(f));
});
