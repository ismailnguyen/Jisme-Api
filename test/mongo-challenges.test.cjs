'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');
test('Mongo adapter sends exactly one atomic findOneAndDelete including binding and expiry',async()=>{
 const filter={challenge:'synthetic',userId:'owner',purpose:'authentication',expiresAt:{$gt:1000}};
 const doc={...filter,expiresAt:2000};const calls=[];
 const collection={findOneAndDelete:async(f,options)=>{calls.push({f,options});return doc;}};
 const context={exports:{},require:name=>{
  if(name.includes('dbConnection'))return {getInstance:async()=>({collection:name=>{assert.equal(name,'webauthn_challenges');return collection;}})};
  if(name==='mongodb')return {ObjectId:class{}};
  if(name.includes('errors'))return {generateError:()=>new Error('Unknown action')};
  throw new Error('Unexpected import');
 }};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../repository/adapters/dbAdapter.js'),'utf8'),context);
 const result=await context.exports.sendQuery('webauthn_challenges',{action:'findOneAndDelete',filter});
 assert.equal(result.data.document,doc);assert.equal(calls.length,1);assert.equal(calls[0].f,filter);assert.equal(calls[0].options.includeResultMetadata,false);
});
test('API repository fails closed rather than approximating atomic consume',async()=>{
 let contacted=false;const context={exports:{},require:name=>{
  if(name.includes('config'))return {db_repository_type:'api'};
  return {sendQuery:async()=>{contacted=true;throw new Error('Must not contact API');}};
 }};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../repository/ports/repositoryPort.js'),'utf8'),context);
 await assert.rejects(context.exports.findOneAndDelete('webauthn_challenges',{filter:{}}),/Atomic WebAuthn/);assert.equal(contacted,false);
});
