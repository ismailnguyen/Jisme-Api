'use strict';
// Regression tests for the vault security review (reports/jisme/vault/api-review.md):
// H1 ABA across delete/re-create, M1 replace freshness, M2 atomic per-user quota,
// L2 auth before PRF walk, L3/L5 documented transport behaviour.
const { test } = require('node:test');
const assert = require('node:assert/strict');

global.__JISME_MOCK_STORE__ = { users: [], accounts: [], activities: [], webauthnChallenges: [], vaultEnvelopes: [] };
// The mock repository is refused in production (L1); 'test' keeps dotenv harmless (no .env file).
process.env.NODE_ENV = 'test';
process.env.DB_REPOSITORY_TYPE = 'mock';
process.env.TOKEN_MASTER_SECRET = 'unit-test-token-secret';

const { sign } = require('jsonwebtoken');
const vault = require('../services/vaultService.js');
const controller = require('../controllers/vaultController.js');
const netlify = require('../netlify/functions/vaults/index.js');

const ct = (bytes, fill = 7) => Buffer.alloc(bytes, fill).toString('base64url');
const envelope = (fill = 7) => ({ v: 1, ct: ct(64, fill) });
const body = (expectedRevision, fill = 7) => ({ expectedRevision, envelope: envelope(fill) });
const nowS = () => Math.floor(Date.now() / 1000);
const bearer = (claims) => ({ authorization: 'Bearer ' + sign(claims, 'unit-test-token-secret', { expiresIn: '1h' }) });
const session = (uuid, authTime = nowS()) => bearer({ uuid, step: 'loggedIn', isAuthorized: true, auth_time: authTime });
const stored = () => global.__JISME_MOCK_STORE__.vaultEnvelopes;
const conflictAt = (revision) => (error) => {
    assert.equal(error.code, 409, `expected 409, got ${error.code} (${error.message}: ${error.reason})`);
    if (revision !== undefined) assert.equal(error.currentRevision, revision);
    return true;
};
const refused = (code) => (error) => {
    assert.equal(error.code, code, `expected ${code}, got ${error.code} (${error.message}: ${error.reason})`);
    return true;
};

// ---------- H1: ABA across delete and re-create ----------

test('H1: stale PUT with a pre-delete revision cannot clobber a re-created vault', async () => {
    await vault.put('aba-1', 'primary', body(0, 1));                 // device A reads rev 1
    await vault.remove('aba-1', 'primary', 1);                        // device B deletes rev 1
    const recreated = await vault.put('aba-1', 'primary', body(0, 2)); // and re-creates
    assert.equal(recreated.created, true);
    assert.ok(recreated.revision > 1, `re-created revision ${recreated.revision} must not reuse a previous revision`);

    // Device A, offline since rev 1, writes "old-style": expectedRevision 1.
    await assert.rejects(vault.put('aba-1', 'primary', body(1, 9)), conflictAt(recreated.revision));
    await assert.rejects(vault.remove('aba-1', 'primary', 1), conflictAt(recreated.revision));
    const current = await vault.get('aba-1', 'primary');
    assert.deepEqual(current.envelope, envelope(2));
    assert.equal(current.revision, recreated.revision);

    // The re-created vault itself works normally.
    const replaced = await vault.put('aba-1', 'primary', body(recreated.revision, 3));
    assert.equal(replaced.revision, recreated.revision + 1);
});

test('H1: revisions never repeat across several delete/re-create cycles', async () => {
    const seen = new Set();
    let revision = (await vault.put('aba-2', 'primary', body(0))).revision;
    for (let cycle = 0; cycle < 4; cycle++) {
        revision = (await vault.put('aba-2', 'primary', body(revision, cycle))).revision;
        assert.equal(seen.has(revision), false);
        seen.add(revision);
        await vault.remove('aba-2', 'primary', revision);
        revision = (await vault.put('aba-2', 'primary', body(0))).revision;
        assert.equal(seen.has(revision), false, `revision ${revision} reused after delete`);
        seen.add(revision);
    }
});

test('H1: a deleted vault keeps no ciphertext and is invisible to get/list/conflict', async () => {
    await vault.put('aba-3', 'gone', body(0, 4));
    await vault.remove('aba-3', 'gone', 1);
    assert.doesNotMatch(JSON.stringify(stored()), new RegExp(ct(64, 4)));
    await assert.rejects(vault.get('aba-3', 'gone'), refused(404));
    assert.deepEqual(await vault.list('aba-3'), []);
    await assert.rejects(vault.put('aba-3', 'gone', body(2)), conflictAt(0));
});

test('H1: concurrent re-creates of a deleted vault: exactly one wins', async () => {
    await vault.put('aba-4', 'primary', body(0));
    await vault.remove('aba-4', 'primary', 1);
    const results = await Promise.allSettled(Array.from({ length: 6 }, (_, i) => vault.put('aba-4', 'primary', body(0, i))));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    assert.ok(results.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 409));
});

test('H1 (HTTP): create → delete → re-create → stale PUT with pre-delete revision is 409', async () => {
    const owner = session('aba-http');
    assert.equal((await controller.put(owner, { vaultId: 'primary' }, body(0, 1))).status, 201);
    assert.equal((await controller.remove(owner, { vaultId: 'primary' }, { expectedRevision: '1' })).status, 200);
    const recreated = await controller.put(owner, { vaultId: 'primary' }, body(0, 2));
    assert.equal(recreated.status, 201);
    const stale = await controller.put(owner, { vaultId: 'primary' }, body(1, 9));
    assert.equal(stale.status, 409);
    assert.equal(stale.data.currentRevision, recreated.data.revision);
    assert.deepEqual((await controller.get(owner, { vaultId: 'primary' })).data.envelope, envelope(2));
});

// ---------- M1: replace needs the same recent sign-in as delete ----------

test('M1: replacing an existing vault requires auth_time within 300 s', async () => {
    const created = await controller.put(session('fresh-1', nowS() - 3600), { vaultId: 'primary' }, body(0, 1));
    assert.equal(created.status, 201, 'creating a new vault does not need a recent sign-in');

    for (const authTime of [nowS() - 301, nowS() - 3600, nowS() + 120]) {
        const r = await controller.put(session('fresh-1', authTime), { vaultId: 'primary' }, body(1, 9));
        assert.equal(r.status, 401);
        assert.match(r.data.error.message, /Reauthentication required/);
    }
    assert.deepEqual((await vault.get('fresh-1', 'primary')).envelope, envelope(1));

    const r = await controller.put(session('fresh-1', nowS() - 10), { vaultId: 'primary' }, body(1, 2));
    assert.equal(r.status, 200);
    assert.equal(r.data.revision, 2);
});

test('M1: a stale session cannot sidestep the delete rule with a junk PUT (Netlify too)', async () => {
    await controller.put(session('fresh-2'), { vaultId: 'primary' }, body(0, 1));
    const stale = session('fresh-2', nowS() - 86400);
    const r = await netlify.handler({ httpMethod: 'PUT', path: '/.netlify/functions/vaults/primary', headers: stale,
        body: JSON.stringify({ expectedRevision: 1, envelope: { v: 1, ct: ct(28, 0) } }), queryStringParameters: null });
    assert.equal(r.statusCode, 401);
    assert.deepEqual((await vault.get('fresh-2', 'primary')).envelope, envelope(1));
});

// ---------- M2: atomic per-user vault limit ----------

test('M2: concurrent creates of distinct vaults cannot overshoot the limit', async () => {
    const max = vault.LIMITS.MAX_VAULTS_PER_USER;
    const results = await Promise.allSettled(Array.from({ length: 3 * max }, (_, i) => vault.put('quota-1', `v${i}`, body(0))));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, max);
    assert.ok(results.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 403));
    assert.equal((await vault.list('quota-1')).length, max);
});

test('M2: deleting a vault frees its slot; re-creating a deleted name needs a free slot', async () => {
    const max = vault.LIMITS.MAX_VAULTS_PER_USER;
    for (let i = 0; i < max; i++) await vault.put('quota-2', `v${i}`, body(0));
    await assert.rejects(vault.put('quota-2', 'extra', body(0)), refused(403));
    await vault.remove('quota-2', 'v0', 1);
    await vault.put('quota-2', 'extra', body(0));
    await assert.rejects(vault.put('quota-2', 'v0', body(0)), refused(403));
    await vault.remove('quota-2', 'v1', 1);
    assert.ok((await vault.put('quota-2', 'v0', body(0))).revision > 1);
    assert.equal((await vault.list('quota-2')).length, max);
});

test('M2: duplicate create at the limit is still a 409, not a 403', async () => {
    const max = vault.LIMITS.MAX_VAULTS_PER_USER;
    for (let i = 0; i < max; i++) await vault.put('quota-3', `v${i}`, body(0));
    await assert.rejects(vault.put('quota-3', 'v3', body(0)), conflictAt(1));
});

test('M2: distinct vault names (live + deleted) are bounded so tombstones cannot grow without limit', async () => {
    const names = vault.LIMITS.MAX_VAULT_NAMES;
    assert.ok(Number.isSafeInteger(names) && names >= vault.LIMITS.MAX_VAULTS_PER_USER);
    for (let i = 0; i < names; i++) {
        await vault.put('quota-4', `n${i}`, body(0));
        await vault.remove('quota-4', `n${i}`, 1);
    }
    await assert.rejects(vault.put('quota-4', 'brand-new', body(0)), refused(403));
    // Re-using a previously used name is still possible.
    assert.equal((await vault.put('quota-4', 'n0', body(0))).created, true);
});

test('M2: quota bookkeeping never stores the raw uuid', async () => {
    await vault.put('quota-uuid-secret', 'primary', body(0));
    assert.doesNotMatch(JSON.stringify(global.__JISME_MOCK_STORE__), /quota-uuid-secret/);
});

// ---------- L2: authenticate before walking the body for PRF names ----------

for (const [name, call] of [
    ['PUT with PRF body', (h) => controller.put(h, { vaultId: 'primary' }, { ...body(0), prf: { first: 'x' } })],
    ['PUT with deeply nested body', (h) => {
        let deep = {};
        for (let i = 0; i < 20000; i++) deep = { a: deep };
        return controller.put(h, { vaultId: 'primary' }, deep);
    }],
    ['DELETE with PRF query', (h) => controller.remove(h, { vaultId: 'primary' }, { expectedRevision: '1', prf: 'x' })],
    ['GET with PRF params', (h) => controller.get(h, { vaultId: 'primary', prfOutput: 'x' })],
]) {
    test(`L2: unauthenticated ${name} is 401, not a 400 PRF walk`, async () => {
        const r = await call({});
        assert.equal(r.status, 401);
    });
}

test('L2: authenticated PRF payloads are still refused with 400', async () => {
    const r = await controller.put(session('l2-user'), { vaultId: 'primary' }, { ...body(0), prf: { first: 'x' } });
    assert.equal(r.status, 400);
    assert.match(r.data.error.reason, /PRF/);
});

// ---------- L3/L5: documented transport behaviour ----------

test('L3: PRF-named query parameters on GET/PUT are ignored, not stored or rejected', async () => {
    const owner = session('l3-user');
    const query = { prf: 'x' };
    let r = await netlify.handler({ httpMethod: 'PUT', path: '/.netlify/functions/vaults/primary', headers: owner,
        body: JSON.stringify(body(0)), queryStringParameters: query });
    assert.equal(r.statusCode, 201);
    r = await netlify.handler({ httpMethod: 'GET', path: '/.netlify/functions/vaults/primary', headers: owner, body: null, queryStringParameters: query });
    assert.equal(r.statusCode, 200);
    assert.doesNotMatch(JSON.stringify(stored()), /"prf"/);
});

test('L5: Netlify base64-encoded bodies are refused with 400 (send application/json)', async () => {
    const r = await netlify.handler({ httpMethod: 'PUT', path: '/.netlify/functions/vaults/primary', headers: session('l5-user'),
        body: Buffer.from(JSON.stringify(body(0))).toString('base64'), isBase64Encoded: true, queryStringParameters: null });
    assert.equal(r.statusCode, 400);
});
