'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');
function controller(){
 const calls=[];const errors=require('../utils/errors.js');
 const context={exports:{},console,require:name=>{
  if(name.includes('userService')) return {verifyPasskey:async()=>{calls.push('verify');return {token:'MUST NOT ISSUE'};},update:async()=>{calls.push('update');return {};}};
  if(name.includes('credentials')) return {verifyAccessToken:async()=>({uuid:'owner',isAuthorized:true,step:'request_passkey',client:{agent:'synthetic'}})};
  if(name.includes('errors')) return errors;
  if(name.includes('webauthnVerifier')) return require('../services/webauthnVerifier.js');
  throw new Error('Unexpected module '+name);
 }};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../controllers/userController.js'),'utf8'),context);
 return {...context.exports,calls};
}
test('legacy passkey controller is closed regardless of supplied proof',async()=>{
 const c=controller();const r=await c.verifyPasskey({}, {passkey:{id:'credential',response:{userHandle:'owner'}}},{agent:'synthetic'});
 assert.equal(r.status,403);assert.match(r.data.error.reason,/password.*re-enroll/i);assert.deepEqual(c.calls,[]);
});
for(const payload of [{prfOutput:'secret'},{passkey:{clientExtensionResults:{prf:{results:{first:'secret'}}}}}])
 test('passkey endpoint explicitly refuses PRF payload '+Object.keys(payload)[0],async()=>{
 const c=controller();const r=await c.verifyPasskey({},payload,{});assert.equal(r.status,400);assert.match(r.data.error.reason,/PRF/);assert.deepEqual(c.calls,[]);
});
test('generic user update explicitly refuses PRF material before service',async()=>{
 const c=controller();const r=await c.update({}, {prfOutput:'secret'});assert.equal(r.status,400);assert.match(r.data.error.reason,/PRF/);assert.deepEqual(c.calls,[]);
});
