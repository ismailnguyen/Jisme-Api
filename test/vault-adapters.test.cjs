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
        if (name.includes('vaultService')) return new Proxy({}, {
            get: (_target, prop) => (prop === 'ownerOf'
                ? () => 'synthetic-owner-hash'
                : async () => { throw new Error('mongodb://admin:***@db.internal'); })
        });
        if (name.includes('vaultRateLimit')) return require('../services/vaultRateLimit.js');
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

// ---------- Review fixes: quota (M2), tombstones (H1), repository allowlist (L1) ----------

function loadQuotaAdapter(collection) {
    const context = { exports: {}, require: (name) => {
        if (name.includes('dbConnection')) return { getInstance: async () => ({ collection: (n) => { assert.equal(n, 'vault_quotas'); return collection; } }) };
        if (name === 'mongodb') return { ObjectId: class { constructor() { throw new Error('quota ids must never become ObjectIds'); } } };
        if (name.includes('errors')) return require('../utils/errors.js');
        throw new Error('Unexpected import ' + name);
    } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../repository/adapters/dbAdapter.js'), 'utf8'), context);
    return context.exports;
}

const reserveRequest = (update) => ({ action: 'reserve', filter: { _id: 'o' }, update });

test('M2: Mongo reserve is one conditional upsert ($push id, $inc names) bounded by the limits', async () => {
    const calls = [];
    const adapter = loadQuotaAdapter({ findOneAndUpdate: async (filter, update, options) => { calls.push({ filter, update, options }); return { _id: 'o', ids: ['primary'], names: 1 }; } });
    const result = await adapter.sendQuery('vault_quotas', reserveRequest({ vaultId: 'primary', maxLive: 8, maxNames: 64, newName: true }));
    same(result, { data: { document: { _id: 'o', ids: ['primary'], names: 1 } } });
    assert.equal(calls.length, 1);
    same(calls[0].filter, { _id: 'o', ids: { $ne: 'primary' }, 'ids.7': { $exists: false }, names: { $lt: 64 } });
    same(calls[0].update, { $push: { ids: 'primary' }, $inc: { names: 1 } });
    assert.equal(calls[0].options.upsert, true);
    assert.equal(calls[0].options.returnDocument, 'after');
    assert.equal(calls[0].options.includeResultMetadata, false);

    // Re-using a deleted name does not count against the name limit.
    await adapter.sendQuery('vault_quotas', reserveRequest({ vaultId: 'old', maxLive: 8, maxNames: 64, newName: false }));
    same(calls[1].filter, { _id: 'o', ids: { $ne: 'old' }, 'ids.7': { $exists: false } });
    same(calls[1].update, { $push: { ids: 'old' }, $inc: { names: 0 } });
});

test('M2: Mongo reserve retries one duplicate-key upsert race, then maps a repeat to "full"', async () => {
    const duplicate = () => { const e = new Error('E11000'); e.code = 11000; return e; };
    let attempts = 0;
    const adapter = loadQuotaAdapter({ findOneAndUpdate: async () => { attempts++; throw duplicate(); } });
    same(await adapter.sendQuery('vault_quotas', reserveRequest({ vaultId: 'v', maxLive: 8, maxNames: 64, newName: true })), { data: { document: null } });
    assert.equal(attempts, 2);

    attempts = 0;
    const racing = loadQuotaAdapter({ findOneAndUpdate: async () => {
        if (attempts++ === 0) throw duplicate();
        return { _id: 'o', ids: ['v'], names: 1 };
    } });
    same(await racing.sendQuery('vault_quotas', reserveRequest({ vaultId: 'v', maxLive: 8, maxNames: 64, newName: true })),
        { data: { document: { _id: 'o', ids: ['v'], names: 1 } } });

    const failing = loadQuotaAdapter({ findOneAndUpdate: async () => { const e = new Error('network'); e.code = 6; throw e; } });
    await assert.rejects(failing.sendQuery('vault_quotas', reserveRequest({ vaultId: 'v', maxLive: 8, maxNames: 64, newName: true })), /network/);
});

test('M2: Mongo release is one conditional $pull', async () => {
    const calls = [];
    const adapter = loadQuotaAdapter({ updateOne: async (filter, update) => { calls.push({ filter, update }); return { modifiedCount: 1 }; } });
    same(await adapter.sendQuery('vault_quotas', { action: 'release', filter: { _id: 'o' }, update: { vaultId: 'v', newName: true } }), { data: { released: true } });
    same(calls[0], { filter: { _id: 'o', ids: 'v' }, update: { $pull: { ids: 'v' }, $inc: { names: -1 } } });
});

for (const update of [{ vaultId: 'v', maxLive: 0, maxNames: 64, newName: true }, { vaultId: 'v', maxLive: 8, maxNames: '64', newName: true },
    { vaultId: { $gt: '' }, maxLive: 8, maxNames: 64, newName: true }, { vaultId: 'v', maxLive: 8, maxNames: 64, newName: 'yes' }]) {
    test(`M2: Mongo reserve refuses malformed limits ${JSON.stringify(update)}`, async () => {
        const adapter = loadQuotaAdapter(new Proxy({}, { get: () => () => { throw new Error('driver must not be called'); } }));
        await assert.rejects(adapter.sendQuery('vault_quotas', reserveRequest(update)), (e) => e.code === 500);
    });
}

test('M2: quota actions are refused on the envelope collection and vice versa', async () => {
    const vaults = loadDbAdapter(new Proxy({}, { get: () => () => { throw new Error('driver must not be called'); } }));
    for (const action of ['reserve', 'release']) {
        await assert.rejects(vaults.sendQuery('vault_envelopes', { action, filter: { _id: 'o' }, update: { vaultId: 'v' } }), (e) => e.code === 500);
    }
    const quotas = loadQuotaAdapter(new Proxy({}, { get: () => () => { throw new Error('driver must not be called'); } }));
    for (const action of ['insertOne', 'findOneAndDelete', 'findOneAndUpdate', 'find', 'count']) {
        await assert.rejects(quotas.sendQuery('vault_quotas', { action, filter: { _id: 'o' }, document: {} }), (e) => e.code === 500);
    }
});

function loadRepository(config) {
    const calls = [];
    const port = new Proxy({}, { get: (_, method) => async (collection, request) => {
        calls.push({ method, collection, request: plain(request) });
        if (method === 'insertOneExclusive') return true;
        if (method === 'findAll') return [];
        if (method === 'releaseSlot') return true;
        return null;
    } });
    const context = { exports: {}, require: (name) => {
        if (name.includes('config')) return config;
        if (name.includes('repositoryPort')) return port;
        if (name === 'node:crypto') return require('node:crypto');
        throw new Error('Unexpected import ' + name);
    } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../repository/vaultEnvelopeRepository.js'), 'utf8'), context);
    return { repo: context.exports, calls };
}

test('H1: replace/delete/revive filters pin live vs tombstone state; delete keeps a ciphertext-free tombstone', async () => {
    const { repo, calls } = loadRepository({ db_repository_type: 'db', node_env: 'production' });
    await repo.compareAndSet('o', 'v', 3, { revision: 4, envelope: { v: 1, ct: 'x' }, size: 1, updatedAt: 't' });
    await repo.compareAndDelete('o', 'v', 4, { updatedAt: 't' });
    await repo.revive('o', 'v', 5, { revision: 6, envelope: { v: 1, ct: 'y' }, size: 1, updatedAt: 't' });
    await repo.findOne('o', 'v');
    await repo.list('o');

    const [set, del, revive, findOne, list] = calls;
    assert.equal(set.method, 'findOneAndUpdate');
    assert.equal(set.request.filter.revision, 3);
    assert.equal(set.request.filter['envelope.v'], 1);
    assert.equal(del.method, 'findOneAndUpdate', 'delete must tombstone, not remove the document');
    assert.equal(del.request.filter.revision, 4);
    assert.equal(del.request.filter['envelope.v'], 1);
    same(del.request.update, { revision: 5, envelope: null, size: 0, updatedAt: 't' });
    assert.equal(revive.method, 'findOneAndUpdate');
    assert.equal(revive.request.filter.revision, 5);
    assert.equal(revive.request.filter.envelope, null);
    assert.ok('envelope' in revive.request.filter);
    assert.equal(findOne.request.filter['envelope.v'], 1);
    assert.equal(list.request.filter['envelope.v'], 1);
    for (const call of [set, del, revive, findOne]) {
        assert.match(call.request.filter._id, /^[0-9a-f]{64}$/);
        assert.equal(call.request.filter.owner, 'o');
        assert.equal(call.request.filter.vaultId, 'v');
    }
});

for (const [name, config, allowed] of [
    ['db in production', { db_repository_type: 'db', node_env: 'production' }, true],
    ['mock outside production', { db_repository_type: 'mock', node_env: 'development' }, true],
    ['mock in production', { db_repository_type: 'mock', node_env: 'production' }, false],
    ['unset type', { db_repository_type: undefined, node_env: 'development' }, false],
    ['unknown type', { db_repository_type: 'sqlite', node_env: 'development' }, false],
    ['api', { db_repository_type: 'api', node_env: 'development' }, false],
]) {
    test(`L1: vault repository allowlist: ${name} -> ${allowed ? 'allowed' : 'refused'}`, async () => {
        const { repo, calls } = loadRepository(config);
        if (allowed) {
            await repo.findOne('o', 'v');
            assert.equal(calls.length, 1);
            return;
        }
        for (const call of [() => repo.list('o'), () => repo.findOne('o', 'v'), () => repo.findAny('o', 'v'),
            () => repo.insert({ owner: 'o', vaultId: 'v' }), () => repo.revive('o', 'v', 1, {}),
            () => repo.compareAndSet('o', 'v', 1, {}), () => repo.compareAndDelete('o', 'v', 1, {}),
            () => repo.reserveSlot('o', 'v', { newName: true }), () => repo.releaseSlot('o', 'v', { newName: true }), () => repo.findQuota('o')]) {
            await assert.rejects(call(), /Mongo repository/);
        }
        assert.equal(calls.length, 0);
    });
}
