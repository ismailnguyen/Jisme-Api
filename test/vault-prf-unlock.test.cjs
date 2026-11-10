'use strict';
// P1 PRF-based vault unlock: the client proves possession of a verified passkey
// in an authentication ceremony (PRF extension requested and evaluated LOCALLY),
// the server returns a short-lived vault unlock token and records per-user
// unlock state. The server never receives PRF inputs or outputs.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');
const vaults = require('../controllers/vaultController.js');
const unlockService = require('../services/vaultUnlockService.js');
const limiter = require('../services/vaultRateLimit.js');
const netlify = require('../netlify/functions/vaults/index.js');

async function enrolled(uuid) {
    h.seedUser(uuid);
    const device = authenticator();
    const options = (await passkeys.enrollmentOptions(h.strong(uuid), {}, h.client)).data;
    const r = await passkeys.enroll(h.strong(uuid), { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 201, JSON.stringify(r.data));
    return device;
}

// "Authenticated" here is an ordinary (even hours-old) full session: unlocking
// is a separate proof, so it does not require a fresh password sign-in.
const session = (uuid) => h.strong(uuid, { authTime: h.nowS() - 3600 });

async function unlockChallenge(uuid) {
    const r = await vaults.unlockOptions(session(uuid), {});
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return r.data;
}

test('unlock requires a fully authenticated session (authenticated != unlocked)', async () => {
    await enrolled('unl-0');
    for (const headers of [{}, h.preAuth('unl-0'), h.bearer({ uuid: 'unl-0', isAuthorized: true })]) {
        assert.equal((await vaults.unlockOptions(headers, {})).status, 401);
        assert.equal((await vaults.unlockPasskey(headers, { challenge: 'A'.repeat(43), response: {} })).status, 401);
    }
    assert.equal(await unlockService.isUnlocked('unl-0'), false, 'signing in does not unlock the vault');
});

test('unlock options: own credentials only, UV required, vault-unlock purpose, no PRF salts from the server', async () => {
    const mine = await enrolled('unl-1');
    await enrolled('unl-1-other');
    const options = await unlockChallenge('unl-1');
    assert.deepEqual(options.allowCredentials.map((c) => c.id), [mine.id]);
    assert.equal(options.userVerification, 'required');
    assert.doesNotMatch(JSON.stringify(options), /prf/i, 'PRF eval inputs are chosen and kept client-side');
    const stored = h.store().webauthnChallenges.find((c) => c.challenge === options.challenge);
    assert.equal(stored.purpose, 'vault-unlock');
});

test('successful unlock returns a short-lived token and records unlock state', async () => {
    const device = await enrolled('unl-2');
    const options = await unlockChallenge('unl-2');
    const before = Date.now();
    const r = await vaults.unlockPasskey(session('unl-2'), { challenge: options.challenge, response: device.assert(options.challenge, { counter: 1 }) });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(typeof r.data.unlockToken, 'string');
    assert.equal(r.data.method, 'passkey');
    const ttl = Date.parse(r.data.expiresAt) - before;
    assert.ok(ttl > 0 && ttl <= 5 * 60 * 1000 + 1000, 'TTL <= 5 minutes');
    assert.doesNotMatch(JSON.stringify(r.data), /prf/i);
    assert.equal(await unlockService.isUnlocked('unl-2'), true);
    assert.equal(await unlockService.verifyUnlockToken('unl-2', r.data.unlockToken), true);
    assert.equal(await unlockService.verifyUnlockToken('unl-1', r.data.unlockToken), false, 'bound to its user');
    assert.ok(h.auditActions('unl-2').includes('vault_unlocked'));
    assert.equal(h.credentials().find((c) => c.credentialId === device.id).counter, 1);
});

test('the unlock token is not a session token and a session token is not an unlock token', async () => {
    const device = await enrolled('unl-3');
    const options = await unlockChallenge('unl-3');
    const { unlockToken } = (await vaults.unlockPasskey(session('unl-3'), { challenge: options.challenge, response: device.assert(options.challenge) })).data;
    assert.equal((await vaults.list({ authorization: 'Bearer ' + unlockToken })).status, 401);
    const sessionToken = session('unl-3').authorization.split(' ')[1];
    assert.equal(await unlockService.verifyUnlockToken('unl-3', sessionToken), false);
});

for (const [name, extensions] of [
    ['prf results', { prf: { results: { first: 'c2VjcmV0LXByZi1vdXRwdXQ' } } }],
    ['prf enabled flag', { prf: { enabled: true } }],
    ['PRF uppercase key', { hmacGetSecret: { PRFOutput: 'secret' } }],
]) {
    test(`unlock refuses PRF material (${name}) with 400; no state, no leak`, async () => {
        const uuid = 'unl-4-' + name.replace(/\W/g, '');
        const device = await enrolled(uuid);
        const options = await unlockChallenge(uuid);
        const r = await vaults.unlockPasskey(session(uuid), { challenge: options.challenge, response: device.assert(options.challenge, { extensions }) });
        assert.equal(r.status, 400);
        assert.match(r.data.error.reason, /PRF/);
        assert.doesNotMatch(JSON.stringify(r.data), /secret|c2VjcmV0/);
        assert.equal(await unlockService.isUnlocked(uuid), false);
        assert.doesNotMatch(JSON.stringify(h.store()), /c2VjcmV0LXByZi1vdXRwdXQ/, 'PRF output never stored');
    });
}

test('a login challenge cannot be redeemed for a vault unlock (purpose binding)', async () => {
    const device = await enrolled('unl-5');
    const login = (await passkeys.loginOptions(h.preAuth('unl-5'), {}, h.client)).data;
    const r = await vaults.unlockPasskey(session('unl-5'), { challenge: login.challenge, response: device.assert(login.challenge) });
    assert.equal(r.status, 401);
    assert.equal(await unlockService.isUnlocked('unl-5'), false);
});

test('clone detection applies to unlock as well', async () => {
    const device = await enrolled('unl-6');
    let options = await unlockChallenge('unl-6');
    assert.equal((await vaults.unlockPasskey(session('unl-6'), { challenge: options.challenge, response: device.assert(options.challenge, { counter: 7 }) })).status, 200);
    options = await unlockChallenge('unl-6');
    const r = await vaults.unlockPasskey(session('unl-6'), { challenge: options.challenge, response: device.assert(options.challenge, { counter: 7 }) });
    assert.equal(r.status, 401);
});

test('another user\'s credential cannot unlock my vault', async () => {
    const theirs = await enrolled('unl-7-owner');
    h.seedUser('unl-7-victim');
    const options = await unlockChallenge('unl-7-victim');
    const r = await vaults.unlockPasskey(session('unl-7-victim'), { challenge: options.challenge, response: theirs.assert(options.challenge) });
    assert.equal(r.status, 403);
    assert.equal(await unlockService.isUnlocked('unl-7-victim'), false);
});

test('lock clears unlock state; expired state is not unlocked', async () => {
    const device = await enrolled('unl-8');
    const options = await unlockChallenge('unl-8');
    const { unlockToken } = (await vaults.unlockPasskey(session('unl-8'), { challenge: options.challenge, response: device.assert(options.challenge) })).data;
    assert.equal((await vaults.lock(session('unl-8'), {})).status, 200);
    assert.equal(await unlockService.isUnlocked('unl-8'), false);
    assert.equal(await unlockService.verifyUnlockToken('unl-8', unlockToken), false);

    const again = await unlockChallenge('unl-8');
    const second = (await vaults.unlockPasskey(session('unl-8'), { challenge: again.challenge, response: device.assert(again.challenge, { counter: 2 }) })).data;
    assert.equal(await unlockService.verifyUnlockToken('unl-8', second.unlockToken, Date.now() + 6 * 60 * 1000), false);
    assert.equal(await unlockService.isUnlocked('unl-8', Date.now() + 6 * 60 * 1000), false);
});

test('unlock endpoints are rate limited per user', async () => {
    await enrolled('unl-rl');
    let last;
    for (let i = 0; i <= limiter.LIMITS.SENSITIVE_PER_WINDOW; i++) last = await vaults.unlockOptions(session('unl-rl'), {});
    assert.equal(last.status, 429);
    assert.ok(Number(last.headers['Retry-After']) >= 1);
});

test('Netlify vaults function routes unlock endpoints; other POSTs stay 405', async () => {
    const device = await enrolled('unl-nf');
    const headers = session('unl-nf');
    let r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/vaults/unlock/passkey/options', headers, body: '{}' });
    assert.equal(r.statusCode, 200, r.body);
    const { challenge } = JSON.parse(r.body);
    r = await netlify.handler({ httpMethod: 'POST', path: '/func/vaults/unlock/passkey', headers, body: JSON.stringify({ challenge, response: device.assert(challenge) }) });
    assert.equal(r.statusCode, 200, r.body);
    r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/vaults/lock', headers, body: '{}' });
    assert.equal(r.statusCode, 200, r.body);
    r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/vaults/primary', headers, body: '{}' });
    assert.equal(r.statusCode, 405);
});

test('Express vault routes mount the unlock endpoints', () => {
    const routes = [];
    const app = { route: (path) => { const r = {}; for (const m of ['get', 'post', 'put', 'delete']) r[m] = () => { routes.push(m.toUpperCase() + ' ' + path); return r; }; return r; } };
    require('../server/routes/vaultUnlockRoutes.js')(app);
    for (const route of ['POST /vaults/unlock/passkey/options', 'POST /vaults/unlock/passkey', 'POST /vaults/lock']) {
        assert.ok(routes.includes(route), route);
    }
});
