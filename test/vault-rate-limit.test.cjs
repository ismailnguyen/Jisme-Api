'use strict';
// Per-owner rate limiting on the vault endpoints (activation checklist item 5).
// Fail-closed fixed-window limiter shared by Express and the Netlify function.
const { test } = require('node:test');
const assert = require('node:assert/strict');

global.__JISME_MOCK_STORE__ = { users: [], accounts: [], activities: [], webauthnChallenges: [], vaultEnvelopes: [] };
process.env.NODE_ENV = 'test';
process.env.DB_REPOSITORY_TYPE = 'mock';
process.env.TOKEN_MASTER_SECRET = 'unit-test-token-secret';

const { sign } = require('jsonwebtoken');
const limiter = require('../services/vaultRateLimit.js');
const controller = require('../controllers/vaultController.js');
const netlify = require('../netlify/functions/vaults/index.js');
const vaultRoutes = require('../server/routes/vaultRoutes.js');

const ct = (bytes, fill = 7) => Buffer.alloc(bytes, fill).toString('base64url');
const body = (expectedRevision, fill = 7) => ({ expectedRevision, envelope: { v: 1, ct: ct(64, fill) } });
const nowS = () => Math.floor(Date.now() / 1000);
const bearer = (claims) => ({ authorization: 'Bearer ' + sign(claims, 'unit-test-token-secret', { expiresIn: '1h' }) });
const session = (uuid, authTime = nowS()) => bearer({ uuid, step: 'loggedIn', isAuthorized: true, auth_time: authTime });
const stored = () => global.__JISME_MOCK_STORE__.vaultEnvelopes;

// ---------- unit: the limiter primitive ----------

test('consume allows exactly READS_PER_WINDOW reads and WRITES_PER_WINDOW writes, budgets independent', () => {
    const owner = 'unit-budgets';
    for (let i = 0; i < limiter.LIMITS.READS_PER_WINDOW; i++) {
        assert.equal(limiter.consume(owner, 'read').allowed, true, `read ${i + 1} must pass`);
    }
    assert.equal(limiter.consume(owner, 'read').allowed, false);
    // Reads exhausted, but the write budget is untouched.
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        assert.equal(limiter.consume(owner, 'write').allowed, true, `write ${i + 1} must pass`);
    }
    assert.equal(limiter.consume(owner, 'write').allowed, false);
    // A different owner is unaffected.
    assert.equal(limiter.consume('unit-other', 'read').allowed, true);
    assert.equal(limiter.consume('unit-other', 'write').allowed, true);
});

test('window reset: denied verdicts carry Retry-After, and the budget returns after the window', () => {
    const realNow = Date.now();
    const start = Math.floor(realNow / limiter.LIMITS.WINDOW_MS) * limiter.LIMITS.WINDOW_MS;
    const now = start + 1000; // 1s into a fresh window
    let clock = now;
    const original = Date.now;
    Date.now = () => clock;
    try {
        const owner = 'unit-reset';
        for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) limiter.consume(owner, 'write', clock);
        const denied = limiter.consume(owner, 'write', clock);
        assert.equal(denied.allowed, false);
        assert.equal(denied.retryAfterSeconds, Math.ceil((limiter.LIMITS.WINDOW_MS - 1000) / 1000));
        assert.ok(denied.retryAfterSeconds >= 1 && denied.retryAfterSeconds <= 60);

        clock = now + limiter.LIMITS.WINDOW_MS + 1; // next window
        assert.equal(limiter.consume(owner, 'write', clock).allowed, true);
    } finally {
        Date.now = original;
    }
});

test('fail closed: unknown kind, missing owner and internal faults all deny', () => {
    assert.equal(limiter.consume('unit-x', 'admin').allowed, false);      // unknown kind
    assert.equal(limiter.consume('', 'write').allowed, false);             // no owner
    assert.equal(limiter.consume(undefined, 'read').allowed, false);
    assert.equal(limiter.consume('unit-x', 'read', NaN).allowed, false);   // broken clock

    // Corrupted internal state must fail closed, not open.
    const originalGet = Map.prototype.get;
    Map.prototype.get = () => { throw new Error('boom'); };
    try {
        assert.equal(limiter.consume('unit-x', 'read').allowed, false);
    } finally {
        Map.prototype.get = originalGet;
    }
    const originalSet = Map.prototype.set;
    Map.prototype.set = () => { throw new Error('boom'); };
    try {
        assert.equal(limiter.consume('unit-y', 'write').allowed, false);
    } finally {
        Map.prototype.set = originalSet;
    }
    // Restored state works again.
    assert.equal(limiter.consume('unit-z', 'read').allowed, true);
});

test('bypass attempts fail closed: environment cannot disable or widen the limiter', () => {
    const before = require.cache[require.resolve('../services/vaultRateLimit.js')];
    delete require.cache[require.resolve('../services/vaultRateLimit.js')];
    try {
        process.env.VAULT_RATE_LIMIT = 'off';
        process.env.VAULT_RATE_LIMIT_DISABLED = '1';
        process.env.VAULT_RATE_LIMIT_READS = '1000000';
        process.env.VAULT_RATE_LIMIT_WRITES = '1000000';
        const fresh = require('../services/vaultRateLimit.js');
        assert.equal(fresh.LIMITS.WRITES_PER_WINDOW, 20);
        assert.equal(fresh.LIMITS.READS_PER_WINDOW, 60);
    } finally {
        delete process.env.VAULT_RATE_LIMIT;
        delete process.env.VAULT_RATE_LIMIT_DISABLED;
        delete process.env.VAULT_RATE_LIMIT_READS;
        delete process.env.VAULT_RATE_LIMIT_WRITES;
        require.cache[require.resolve('../services/vaultRateLimit.js')] = before;
    }
});

// ---------- HTTP: enforcement at the shared controller boundary ----------

test('writes over the limit get 429 with a generic body and Retry-After, storage untouched', async () => {
    const owner = session('flood-writes');
    let revision = 0;
    let r;
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        r = await controller.put(owner, { vaultId: 'primary' }, body(revision));
        assert.equal(r.status, i === 0 ? 201 : 200, `write ${i + 1} must pass`);
        revision = r.data.revision;
    }
    r = await controller.put(owner, { vaultId: 'w-over' }, body(0));
    assert.equal(r.status, 429);
    assert.match(r.data.error.message, /Too many vault requests/);
    // Generic body: no owner hash, no uuid, no limiter internals, no driver details.
    assert.doesNotMatch(JSON.stringify(r.data), /flood-writes|Map|bucket|window|Mongo|mock/i);
    assert.ok(r.headers && /^\d+$/.test(r.headers['Retry-After']));
    const retryAfter = Number(r.headers['Retry-After']);
    assert.ok(retryAfter >= 1 && retryAfter <= 60);
    // The rejected write never reached storage.
    assert.equal(stored().some((doc) => doc.vaultId === 'w-over'), false);
    // Reads are a separate budget: the flooded writer can still read.
    assert.equal((await controller.get(owner, { vaultId: 'primary' })).status, 200);
    // Deletes count as writes too.
    assert.equal((await controller.remove(owner, { vaultId: 'primary' }, { expectedRevision: String(revision) })).status, 429);
});

test('reads over the limit get 429; another user is unaffected', async () => {
    const owner = session('flood-reads');
    assert.equal((await controller.put(owner, { vaultId: 'primary' }, body(0))).status, 201);
    let r;
    for (let i = 0; i < limiter.LIMITS.READS_PER_WINDOW; i++) {
        r = await controller.get(owner, { vaultId: 'primary' });
        assert.equal(r.status, 200, `read ${i + 1} must pass`);
    }
    r = await controller.get(owner, { vaultId: 'primary' });
    assert.equal(r.status, 429);
    assert.ok(r.headers && Number(r.headers['Retry-After']) >= 1 && Number(r.headers['Retry-After']) <= 60);
    // list shares the read budget.
    assert.equal((await controller.list(owner)).status, 429);
    // Per-user isolation: a different user still works.
    const other = session('flood-other');
    assert.equal((await controller.get(other, { vaultId: 'primary' })).status, 404);
    assert.equal((await controller.put(other, { vaultId: 'primary' }, body(0))).status, 201);
});

test('the limit resets when the window rolls over (controller level)', async () => {
    const owner = session('flood-reset');
    let revision = 0;
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        const r = await controller.put(owner, { vaultId: 'primary' }, body(revision));
        assert.equal(r.status, i === 0 ? 201 : 200);
        revision = r.data.revision;
    }
    assert.equal((await controller.put(owner, { vaultId: 'primary' }, body(revision))).status, 429);
    const original = Date.now;
    Date.now = () => original() + limiter.LIMITS.WINDOW_MS + 1000;
    try {
        assert.equal((await controller.put(owner, { vaultId: 'r-over' }, body(0))).status, 201);
    } finally {
        Date.now = original;
    }
});

test('429 comes after authentication: unauthenticated floods stay 401 and consume nothing', async () => {
    const before = stored().length;
    for (let i = 0; i < 5; i++) {
        assert.equal((await controller.put({}, { vaultId: 'primary' }, body(0))).status, 401);
        assert.equal((await controller.get({ authorization: 'Bearer junk' }, { vaultId: 'primary' })).status, 401);
    }
    assert.equal(stored().length, before);
    // The authenticated owner was never counted.
    const owner = session('flood-auth-order');
    let revision = 0;
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        const r = await controller.put(owner, { vaultId: 'primary' }, body(revision));
        assert.equal(r.status, i === 0 ? 201 : 200);
        revision = r.data.revision;
    }
});

// ---------- transport plumbing: Retry-After reaches both Express and Netlify ----------

test('Netlify function surfaces Retry-After on 429', async () => {
    const owner = session('flood-netlify');
    const call = (payload) => netlify.handler({ httpMethod: 'PUT', path: '/.netlify/functions/vaults/primary',
        headers: owner, body: JSON.stringify(payload), queryStringParameters: null });
    let revision = 0;
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        const r = await call(body(revision));
        assert.equal(r.statusCode, i === 0 ? 201 : 200);
        revision = JSON.parse(r.body).revision;
    }
    const denied = await call(body(revision));
    assert.equal(denied.statusCode, 429);
    assert.match(JSON.parse(denied.body).error.message, /Too many vault requests/);
    assert.ok(denied.headers['Retry-After']);
    assert.ok(Number(denied.headers['Retry-After']) >= 1 && Number(denied.headers['Retry-After']) <= 60);
});

test('Express route surfaces Retry-After on 429', async () => {
    const owner = session('flood-express');
    const calls = [];
    const app = { route: () => {
        const chainable = {};
        for (const method of ['get', 'put', 'delete']) {
            chainable[method] = (handler) => { calls.push([method.toUpperCase(), handler]); return chainable; };
        }
        return chainable;
    } };
    vaultRoutes(app);
    const putHandler = calls.find(([m]) => m === 'PUT')[1];
    const expressResponse = () => {
        const state = { code: 0, headers: {}, data: null };
        state.status = (code) => { state.code = code; return state; };
        state.set = (headers) => { Object.assign(state.headers, headers); return state; };
        state.json = (data) => { state.data = data; return state; };
        return state;
    };
    let revision = 0;
    for (let i = 0; i < limiter.LIMITS.WRITES_PER_WINDOW; i++) {
        const response = expressResponse();
        await putHandler({ headers: owner, params: { vaultId: 'primary' }, body: body(revision) }, response);
        assert.equal(response.code, i === 0 ? 201 : 200);
        revision = response.data.revision;
    }
    const response = expressResponse();
    await putHandler({ headers: owner, params: { vaultId: 'e-over' }, body: body(0) }, response);
    assert.equal(response.code, 429);
    assert.match(JSON.stringify(response.data), /Too many vault requests/);
    assert.ok(response.headers['Retry-After']);
    assert.ok(Number(response.headers['Retry-After']) >= 1 && Number(response.headers['Retry-After']) <= 60);
});
