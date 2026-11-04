'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../services/userService.js'),'utf8');
function service(){
 const start=source.indexOf('const verifyPasskey = async function(');
 const end=source.indexOf('\nconst login = async function(',start);
 let authenticated=false;
 const context=vm.createContext({encrypt:x=>x,decrypt:x=>x,findUser:async()=>({uuid:'owner',email:'test@example.invalid',passkeys:[{passkey:{id:'credential'}}]}),login:async()=>{authenticated=true;},generateError:(message,reason,code)=>Object.assign(new Error(reason),{code})});
 vm.runInContext(source.slice(start,end)+'\nthis.verifyPasskey=verifyPasskey;',context);
 return {context,authenticated:()=>authenticated};
}
test('legacy identifier-only service cannot mint login; clear recovery path',async()=>{
 const s=service();
 await assert.rejects(s.context.verifyPasskey('credential','owner',false,{}), /password.*re-enroll/i);
 assert.equal(s.authenticated(),false);
});
function isolate(name,end,globals={}){
 const start=source.indexOf('const '+name+' = async function(');
 const finish=source.indexOf('\nconst '+end,start);
 const ctx=vm.createContext({generateError:(message,reason,code)=>Object.assign(new Error(reason),{code}),...globals});
 vm.runInContext(source.slice(start,finish)+'\nthis.call='+name+';',ctx);
 return ctx.call;
}
test('legacy credentials do not steer login into disabled passkey flow',async()=>{
 const call=isolate('requestLogin','verifyPassword',{
  findUser:async()=>({email:'e',uuid:'u',passkeys:[{passkey:{id:'legacy'}}]}),encrypt:x=>x,
  requestPassKeyVerification:()=>({next:'passkey'}),requestPasswordVerification:()=>({next:'password'})
 });
 assert.equal((await call('e',{})).next,'password');
});
test('generic update cannot enroll client-supplied passkeys',async()=>{
 const call=isolate('update','getInformation',{});
 await assert.rejects(call({email:'e',uuid:'u'},{passkeys:[]}), /verified enrollment/i);
});
