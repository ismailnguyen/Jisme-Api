'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const {fixture,registrationFixture,config}=require('./fixtures.cjs');
process.env.NODE_ENV='production';process.env.DB_REPOSITORY_TYPE='mock';
global.__JISME_MOCK_STORE__={users:[],accounts:[],activities:[],webauthnChallenges:[]};
const challenges=require('../repository/webauthnChallengeRepository.js');
const file=path.join(__dirname,'../services/webauthnCeremonies.js');
let now=1000000;
function ceremonies(session={uuid:'owner',isAuthorized:true,auth_time:1000}){
 assert.ok(fs.existsSync(file),'standalone ceremony paths missing');
 return require(file).createCeremonies({config,challenges,verifySession:async()=>session,clock:()=>now});
}
test('standalone login options and assertion consume persistent challenge exactly once',async()=>{
 const service=ceremonies();const options=await service.authenticationOptions('owner',[]);
 assert.equal(options.rpId,config.rpID);assert.equal(options.userVerification,'required');
 const f=fixture({challenge:options.challenge});
 const results=await Promise.allSettled(Array.from({length:10},()=>service.authentication(f)));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
});
test('standalone enrollment requires fresh verified session and consumes registration challenge',async()=>{
 const service=ceremonies();const options=await service.registrationOptions('Bearer synthetic','owner@example.invalid');
 assert.equal(options.authenticatorSelection.userVerification,'required');assert.equal(options.rp.id,config.rpID);
 const f=registrationFixture({challenge:options.challenge});
 const result=await service.registration('Bearer synthetic',f);
 assert.equal(result.userId,'owner');assert.equal(result.validated,true);
 await assert.rejects(service.registration('Bearer synthetic',f),/consumed/);
});
for(const [name,session] of [['absent',null],['pre-auth',{uuid:'owner',isAuthorized:false,auth_time:1000}],['legacy missing freshness',{uuid:'owner',isAuthorized:true}],['stale',{uuid:'owner',isAuthorized:true,auth_time:699}],['future',{uuid:'owner',isAuthorized:true,auth_time:1001}]])
 test('enrollment rejects '+name+' session',async()=>{
  const service=ceremonies(session);await assert.rejects(service.registrationOptions('Bearer synthetic','name'),/fresh/i);
 });
test('wrong user and wrong purpose cannot burn another ceremony challenge',async()=>{
 const service=ceremonies();const opts=await service.authenticationOptions('owner',[]);
 const f=fixture({challenge:opts.challenge});
 await assert.rejects(service.authentication({...f,userId:'other'}),/challenge/);
 await assert.rejects(service.registration('Bearer synthetic',registrationFixture({challenge:opts.challenge})),/challenge/);
 assert.equal((await service.authentication(f)).newCounter,1);
});
test('ceremony rejects expired challenge and burns invalid signature attempts',async()=>{
 const service=ceremonies();let opts=await service.authenticationOptions('owner',[]);
 now+=300000;await assert.rejects(service.authentication(fixture({challenge:opts.challenge})),/expired/);now-=300000;
 opts=await service.authenticationOptions('owner',[]);const f=fixture({challenge:opts.challenge});
 const bad=structuredClone(f);bad.response.response.signature='AA';
 await assert.rejects(service.authentication(bad));await assert.rejects(service.authentication(f),/consumed/);
});
