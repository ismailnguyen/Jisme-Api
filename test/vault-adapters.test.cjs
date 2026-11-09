'use strict';
// Storage-boundary contracts for vault envelopes: the Mongo adapter uses single
// atomic driver operations without ObjectId rewriting; unsupported repositories
// and unexpected failures fail closed.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

// Objects built inside a vm context have a foreign Object.prototype; compare structure only.
const plain = (value) => JSON.parse(JSON.stringify(value));
const same = (actual, expected) => assert.deepEqual(plain(actual), plain(expected));

function loadDbAdapter(collection) {
    const context = { exports: {}, require: (name) => {
        if (name.includes('dbConnection')) return { getInstance: async () => ({ collection: (n) => { assert.equal(n, 'vault_envelopes'); return collection; } }) };
        if (name === 'mongodb') return { ObjectId: class { constructor() { throw new Error('vault ids must never become ObjectIds'); } } };
        if (name.includes('errors')) return require('../utils/errors.js');
        throw new Error('Unexpected import ' + name);
    } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../repository/adapters/dbAdapter.js'), 'utf8'), context);
    return context.exports;
}

test('Mongo insertOne keeps the deterministic string _id and reports duplicates as conflicts', async () => {
    const calls = [];
    let duplicate = false;
    const adapter = loadDbAdapter({ insertOne: async (doc) => {
        calls.push(structuredClone(doc));
        if (duplicate) { const e = new Error('E11000 duplicate key'); e.code = 11000; throw e; }
        return { insertedId: doc._id };
    } });
    const document = { _id: 'a'.repeat(64), owner: 'b'.repeat(64), vaultId: 'primary', revision: 1 };
    same(await adapter.sendQuery('vault_envelopes', { action: 'insertOne', document }), { data: { inserted: true } });
    assert.equal(calls[0]._id, 'a'.repeat(64));
    duplicate = true;
    same(await adapter.sendQuery('vault_envelopes', { action: 'insertOne', document }), { data: { inserted: false } });
});

test('Mongo insertOne rethrows non-duplicate errors (fail closed)', async () => {
    const adapter = loadDbAdapter({ insertOne: async () => { const e = new Error('network'); e.code = 6; throw e; } });
    await assert.rejects(adapter.sendQuery('vault_envelopes', { action: 'insertOne', document: { _id: 'x' } }), /network/);
});

test('Mongo replace is exactly one findOneAndUpdate with revision predicate', async () => {
    const calls = [];
    const after = { _id: 'id', revision: 3 };
    const adapter = loadDbAdapter({ findOneAndUpdate: async (filter, update, options) => { calls.push({ filter, update, options }); return after; } });
    const filter = { _id: 'id', owner: 'o', vaultId: 'primary', revision: 2 };
    const set = { revision: 3, envelope: { v: 1, ct: 'x' } };
    const result = await adapter.sendQuery('vault_envelopes', { action: 'findOneAndUpdate', filter, update: set });
    assert.equal(result.data.document, after);
    assert.equal(calls.length, 1);
    same(calls[0].filter, filter);
    assert.equal(calls[0].filter._id, 'id');
    same(calls[0].update, { $set: set });
    assert.equal(calls[0].options.returnDocument, 'after');
    assert.equal(calls[0].options.includeResultMetadata, false);
    assert.equal(calls[0].options.upsert, false);
});

test('Mongo delete is exactly one findOneAndDelete with revision predicate', async () => {
    const calls = [];
    const adapter = loadDbAdapter({ findOneAndDelete: async (filter, options) => { calls.push({ filter, options }); return null; } });
    const filter = { _id: 'id', owner: 'o', vaultId: 'primary', revision: 2 };
    const result = await adapter.sendQuery('vault_envelopes', { action: 'findOneAndDelete', filter });
    same(result, { data: { document: null } });
    same(calls[0].filter, filter);
    assert.equal(calls[0].options.includeResultMetadata, false);
});

test('Mongo list/read/count are owner-scoped and list projects out ciphertext', async () => {
    const calls = [];
    const adapter = loadDbAdapter({
        find: (filter, options) => { calls.push(['find', filter, options]); return { toArray: async () => [] }; },
        findOne: async (filter) => { calls.push(['findOne', filter]); return null; },
        countDocuments: async (filter) => { calls.push(['count', filter]); return 0; },
    });
    same(await adapter.sendQuery('vault_envelopes', { action: 'find', filter: { owner: 'o' }, projection: { envelope: 0 } }), { data: { documents: [] } });
    same(await adapter.sendQuery('vault_envelopes', { action: 'findOne', filter: { _id: 'id', owner: 'o' } }), { data: { document: null } });
    assert.equal(await adapter.sendQuery('vault_envelopes', { action: 'count', filter: { owner: 'o' } }), 0);
    same(calls[0], ['find', { owner: 'o' }, { projection: { envelope: 0 } }]);
    same(calls[1], ['findOne', { _id: 'id', owner: 'o' }]);
});

for (const action of ['updateOne', 'deleteOne', 'insertMany', 'aggregate', 'replaceOne']) {
    test(`Mongo vault branch refuses unsupported action ${action}`, async () => {
        const adapter = loadDbAdapter(new Proxy({}, { get: () => () => { throw new Error('driver must not be called'); } }));
        await assert.rejects(adapter.sendQuery('vault_envelopes', { action, filter: {}, update: {}, document: {}, documents: [] }), (e) => e.code === 500);
    });
}

test('vault repository refuses the Data API adapter without contacting it', async () => {
    let contacted = false;
    const context = { exports: {}, require: (name) => {
        if (name.includes('config')) return { db_repository_type: 'api' };
        return new Proxy({}, { get: () => async () => { contacted = true; throw new Error('must not contact'); } });
    } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../repository/vaultEnvelopeRepository.js'), 'utf8'), context);
    const repo = context.exports;
    const doc = { _id: 'i', owner: 'o', vaultId: 'v', revision: 1 };
    for (const call of [() => repo.list('o'), () => repo.findOne('o', 'v'), () => repo.count('o'), () => repo.insert(doc),
        () => repo.compareAndSet('o', 'v', 1, {}), () => repo.compareAndDelete('o', 'v', 1)]) {
        await assert.rejects(call(), /Mongo repository/);
    }
    assert.equal(contacted, false);
});

test('controller maps unexpected storage failures to a generic 503 without internals', async () => {
    const context = { exports: {}, console, require: (name) => {
        if (name.includes('vaultService')) return new Proxy({}, { get: () => async () => { throw new Error('mongodb://admin:hunter2@db.internal'); } });
        if (name.includes('credentials')) return { verifyAccessToken: async () => ({ uuid: 'u', isAuthorized: true, auth_time: Math.floor(Date.now() / 1000) }) };
        if (name.includes('errors')) return require('../utils/errors.js');
        if (name.includes('webauthnVerifier')) return require('../services/webauthnVerifier.js');
        throw new Error('Unexpected module ' + name);
    } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../controllers/vaultController.js'), 'utf8'), context);
    const c = context.exports;
    const headers = { authorization: 'Bearer synthetic' };
    for (const r of [await c.list(headers), await c.get(headers, { vaultId: 'v' }),
        await c.put(headers, { vaultId: 'v' }, {}), await c.remove(headers, { vaultId: 'v' }, { expectedRevision: '1' })]) {
        assert.equal(r.status, 503);
        assert.doesNotMatch(JSON.stringify(r.data), /hunter2|mongodb|internal/);
    }
});
