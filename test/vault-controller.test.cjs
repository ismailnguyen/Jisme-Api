'use strict';
// Vault endpoints: trusted auth_time session, PRF guard, delete freshness,
// HTTP mapping, and both transports (Netlify function + Express routes).
const { test } = require('node:test');
const assert = require('node:assert/strict');

global.__JISME_MOCK_STORE__ = { users: [], accounts: [], activities: [], webauthnChallenges: [], vaultEnvelopes: [] };
// The vault repository refuses the mock adapter in production (review L1).
process.env.NODE_ENV = 'test';
process.env.DB_REPOSITORY_TYPE = 'mock';
process.env.TOKEN_MASTER_SECRET = 'unit-test-token-secret';

const { sign } = require('jsonwebtoken');
const controller = require('../controllers/vaultController.js');

const nowS = () => Math.floor(Date.now() / 1000);
const bearer = (claims, secret = 'unit-test-token-secret') => ({ authorization: 'Bearer ' + sign(claims, secret, { expiresIn: '1h' }) });
const session = (uuid, authTime = nowS()) => bearer({ uuid, email: `${uuid}@example.invalid`, step: 'loggedIn', isAuthorized: true, auth_time: authTime });
const ct = (bytes, fill = 7) => Buffer.alloc(bytes, fill).toString('base64url');
const body = (expectedRevision, fill = 7) => ({ expectedRevision, envelope: { v: 1, ct: ct(64, fill) } });
const stored = () => global.__JISME_MOCK_STORE__.vaultEnvelopes;

const badSessions = {
    'missing header': {},
    'no bearer token': { authorization: 'Bearer' },
    'wrong signing secret': bearer({ uuid: 'u', isAuthorized: true, auth_time: nowS() }, 'other-secret'),
    'pre-auth token': bearer({ uuid: 'u', step: 'request_password', isAuthorized: false }),
    'legacy token without auth_time': bearer({ uuid: 'u', step: 'loggedIn', isAuthorized: true }),
    'non-integer auth_time': bearer({ uuid: 'u', isAuthorized: true, auth_time: '1700000000' }),
    'missing uuid': bearer({ isAuthorized: true, auth_time: nowS() }),
};

for (const [name, headers] of Object.entries(badSessions)) {
    test(`every vault endpoint rejects ${name} with 401 before storage`, async () => {
        const before = stored().length;
        const results = [
            await controller.list(headers),
            await controller.get(headers, { vaultId: 'primary' }),
            await controller.put(headers, { vaultId: 'primary' }, body(0)),
            await controller.remove(headers, { vaultId: 'primary' }, { expectedRevision: '1' }),
        ];
        for (const result of results) assert.equal(result.status, 401);
        assert.equal(stored().length, before);
    });
}

test('authenticated lifecycle: create 201, read, list, replace 200, stale 409 without envelope, delete', async () => {
    const owner = session('owner-1');
    let r = await controller.put(owner, { vaultId: 'primary' }, body(0, 1));
    assert.equal(r.status, 201);
    assert.deepEqual(Object.keys(r.data).sort(), ['revision', 'updatedAt', 'vaultId']);

    r = await controller.get(owner, { vaultId: 'primary' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.envelope, { v: 1, ct: ct(64, 1) });

    r = await controller.list(owner);
    assert.equal(r.status, 200);
    assert.equal(r.data.vaults.length, 1);

    r = await controller.put(owner, { vaultId: 'primary' }, body(1, 2));
    assert.equal(r.status, 200);
    assert.equal(r.data.revision, 2);

    r = await controller.put(owner, { vaultId: 'primary' }, body(1, 3));
    assert.equal(r.status, 409);
    assert.equal(r.data.currentRevision, 2);
    assert.doesNotMatch(JSON.stringify(r.data), new RegExp(ct(64, 2)));

    r = await controller.remove(owner, { vaultId: 'primary' }, { expectedRevision: '2' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data, { vaultId: 'primary', deleted: true });

    r = await controller.get(owner, { vaultId: 'primary' });
    assert.equal(r.status, 404);
});

test('owner comes from the token only; another session cannot read it', async () => {
    await controller.put(session('owner-2'), { vaultId: 'primary' }, body(0, 4));
    const r = await controller.get(session('intruder'), { vaultId: 'primary' });
    assert.equal(r.status, 404);
    const spoof = await controller.put(session('intruder'), { vaultId: 'primary' }, { ...body(1), uuid: 'owner-2' });
    assert.equal(spoof.status, 400);
});

for (const [name, payload] of [
    ['top-level prfOutput', { ...body(0), prfOutput: 'secret' }],
    ['nested envelope.prf', { expectedRevision: 0, envelope: { v: 1, ct: ct(64), prf: { first: 'secret' } } }],
    ['deep clientExtensionResults.prf', { expectedRevision: 0, envelope: { v: 1, ct: ct(64) }, meta: { clientExtensionResults: { prf: {} } } }],
]) {
    test(`PUT refuses PRF material (${name}) before storage`, async () => {
        const before = stored().length;
        const r = await controller.put(session('prf-user'), { vaultId: 'primary' }, payload);
        assert.equal(r.status, 400);
        assert.match(r.data.error.reason, /PRF/);
        assert.doesNotMatch(JSON.stringify(r.data), /secret/);
        assert.equal(stored().length, before);
    });
}

test('DELETE refuses PRF material in query', async () => {
    const r = await controller.remove(session('prf-user'), { vaultId: 'primary' }, { expectedRevision: '1', prf: 'secret' });
    assert.equal(r.status, 400);
    assert.match(r.data.error.reason, /PRF/);
});

test('DELETE requires recent authentication (auth_time <= 300s, not in the future)', async () => {
    await controller.put(session('owner-3'), { vaultId: 'primary' }, body(0));
    for (const authTime of [nowS() - 301, nowS() - 3600, nowS() + 120]) {
        const r = await controller.remove(session('owner-3', authTime), { vaultId: 'primary' }, { expectedRevision: '1' });
        assert.equal(r.status, 401);
        assert.match(r.data.error.message, /Reauthentication required/);
    }
    // Reads/writes with an older session are still fine.
    assert.equal((await controller.get(session('owner-3', nowS() - 3600), { vaultId: 'primary' })).status, 200);
    const r = await controller.remove(session('owner-3', nowS() - 10), { vaultId: 'primary' }, { expectedRevision: '1' });
    assert.equal(r.status, 200);
});

for (const query of [{}, { expectedRevision: '' }, { expectedRevision: '01' }, { expectedRevision: '1.0' }, { expectedRevision: 'abc' }, { expectedRevision: '-1' }, { expectedRevision: ['1', '2'] }, undefined]) {
    test(`DELETE rejects malformed expectedRevision ${JSON.stringify(query)}`, async () => {
        const r = await controller.remove(session('owner-4'), { vaultId: 'primary' }, query);
        assert.equal(r.status, 400);
    });
}

test('oversize ciphertext maps to 413; unknown version maps to 400', async () => {
    let r = await controller.put(session('owner-5'), { vaultId: 'primary' }, { expectedRevision: 0, envelope: { v: 1, ct: ct(524289) } });
    assert.equal(r.status, 413);
    r = await controller.put(session('owner-5'), { vaultId: 'primary' }, { expectedRevision: 0, envelope: { v: 2, ct: ct(64) } });
    assert.equal(r.status, 400);
});

// ---------- Netlify transport ----------
const netlify = require('../netlify/functions/vaults/index.js');
const event = (httpMethod, path, { headers = {}, body, query } = {}) => ({
    httpMethod, path, headers, body: body === undefined ? null : body, queryStringParameters: query || null,
});

test('Netlify vaults function routes all methods and fails closed', async () => {
    const owner = session('nf-owner');
    let r = await netlify.handler(event('OPTIONS', '/.netlify/functions/vaults'));
    assert.equal(r.statusCode, 200);
    assert.ok(r.headers['Access-Control-Allow-Methods']);

    r = await netlify.handler(event('PUT', '/.netlify/functions/vaults/primary', { headers: owner, body: JSON.stringify(body(0, 9)) }));
    assert.equal(r.statusCode, 201, r.body);
    assert.equal(r.headers['Access-Control-Allow-Origin'], '*');

    r = await netlify.handler(event('GET', '/func/vaults/primary', { headers: owner }));
    assert.equal(r.statusCode, 200);
    assert.deepEqual(JSON.parse(r.body).envelope, { v: 1, ct: ct(64, 9) });

    r = await netlify.handler(event('GET', '/.netlify/functions/vaults', { headers: owner }));
    assert.equal(r.statusCode, 200);
    assert.equal(JSON.parse(r.body).vaults.length, 1);

    r = await netlify.handler(event('GET', '/.netlify/functions/vaults/', { headers: owner }));
    assert.equal(r.statusCode, 200);

    r = await netlify.handler(event('PUT', '/.netlify/functions/vaults/primary', { headers: owner, body: '{not json' }));
    assert.equal(r.statusCode, 400);

    r = await netlify.handler(event('PUT', '/.netlify/functions/vaults', { headers: owner, body: JSON.stringify(body(0)) }));
    assert.equal(r.statusCode, 400);

    r = await netlify.handler(event('PUT', '/.netlify/functions/vaults/primary/extra', { headers: owner, body: JSON.stringify(body(1)) }));
    assert.equal(r.statusCode, 400);

    r = await netlify.handler(event('POST', '/.netlify/functions/vaults/primary', { headers: owner, body: '{}' }));
    assert.equal(r.statusCode, 405);

    r = await netlify.handler(event('PUT', '/.netlify/functions/vaults/primary', { headers: {}, body: JSON.stringify(body(1)) }));
    assert.equal(r.statusCode, 401);

    r = await netlify.handler(event('DELETE', '/.netlify/functions/vaults/primary', { headers: owner, query: { expectedRevision: '1' } }));
    assert.equal(r.statusCode, 200, r.body);
});

// ---------- Express transport ----------
test('Express routes mount /vaults with a bounded dedicated JSON parser', async (t) => {
    const server = require('../server/server.js');
    const app = await server.init(require('../server/routes/index.js'));
    const listener = await new Promise((resolve) => { const l = app.listen(0, '127.0.0.1', () => resolve(l)); });
    t.after(() => listener.close());
    const base = `http://127.0.0.1:${listener.address().port}`;
    const owner = session('express-owner');
    const call = (method, path, payload) => fetch(base + path, {
        method, headers: { ...owner, 'content-type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload),
    });

    // ~400 KiB envelope exceeds the default 100 kB parser but is within vault limits.
    let r = await call('PUT', '/vaults/primary', { expectedRevision: 0, envelope: { v: 1, ct: ct(400 * 1024) } });
    assert.equal(r.status, 201);
    r = await call('GET', '/vaults/primary');
    assert.equal(r.status, 200);
    assert.equal((await r.json()).envelope.ct.length, ct(400 * 1024).length);
    r = await call('GET', '/vaults');
    assert.equal(r.status, 200);
    r = await call('PUT', '/vaults/primary', { expectedRevision: 0, envelope: { v: 1, ct: ct(64) } });
    assert.equal(r.status, 409);
    r = await call('DELETE', '/vaults/primary?expectedRevision=1');
    assert.equal(r.status, 200);

    // Bodies above the transport limit are refused by the parser.
    r = await call('PUT', '/vaults/huge', { expectedRevision: 0, envelope: { v: 1, ct: ct(1024 * 1024) } });
    assert.equal(r.status, 413);
    // Other routes keep the default parser limit.
    r = await fetch(base + '/users/', { method: 'PUT', headers: { ...owner, 'content-type': 'application/json' }, body: JSON.stringify({ avatarUrl: 'x'.repeat(200 * 1024) }) });
    assert.equal(r.status, 413);
});
