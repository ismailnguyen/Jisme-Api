'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs');
// Synthetic store prevents checked-in mock fixtures/config/secrets being loaded.
global.__JISME_MOCK_STORE__={users:[],accounts:[],activities:[],webauthnChallenges:[]};
process.env.NODE_ENV='production';process.env.DB_REPOSITORY_TYPE='mock';
const file=path.join(__dirname,'../repository/webauthnChallengeRepository.js');
function store(){assert.ok(fs.existsSync(file),'persistent challenge repository missing');return require(file);}
test('challenge is bounded, user/purpose bound and atomically usable once under concurrency',async()=>{
 const repo=store(); const challenge=await repo.issue('owner','authentication',1000);
 assert.match(challenge,/^[A-Za-z0-9_-]{43}$/);
 assert.equal(await repo.consume(challenge,'other','authentication',1001),null);
 assert.equal(await repo.consume(challenge,'owner','registration',1001),null);
 const results=await Promise.all(Array.from({length:20},()=>repo.consume(challenge,'owner','authentication',1001)));
 assert.equal(results.filter(Boolean).length,1);
 assert.equal(await repo.consume(challenge,'owner','authentication',1001),null);
});
test('expired challenge cannot be consumed even without TTL cleanup',async()=>{
 const repo=store();const c=await repo.issue('owner','registration',1000);
 assert.equal(await repo.consume(c,'owner','registration',301000),null);
});
