'use strict';
// P1 passkey login: real verifyAuthenticationResponse against credentials that
// went through verified enrollment. Expected rpID/origin, user verification,
// sign-count clone detection, per-user allowCredentials, single-use challenges.
// Legacy (unvalidated) passkeys keep failing with the re-enrollment 403.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator, b64 } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');
const users = require('../controllers/userController.js');
const limiter = require('../services/vaultRateLimit.js');
const netlify = require('../netlify/functions/users/index.js');

async function enrolled(uuid, opts) {
    h.seedUser(uuid, opts);
    const device = authenticator();
    const options = (await passkeys.enrollmentOptions(h.strong(uuid), {}, h.client)).data;
    const r = await passkeys.enroll(h.strong(uuid), { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 201, JSON.stringify(r.data));
    return device;
}

async function loginChallenge(uuid) {
    const r = await passkeys.loginOptions(h.preAuth(uuid), {}, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return r.data;
}

const handle = (uuid) => b64(Buffer.from(uuid));

test('requestLogin advertises hasPasskey only for verified enrollments', async () => {
    await enrolled('log-1');
    h.seedUser('log-legacy', { legacyPasskeys: [{ passkey: { id: 'legacy-cred' } }] });
    const a = await users.login({ email: h.email('log-1') }, h.client);
    assert.equal(a.status, 200);
    assert.equal(a.data.hasPasskey, true);
    const b = await users.login({ email: h.email('log-legacy') }, h.client);
    assert.equal(b.data.hasPasskey, false);
});

test('authentication options: allowCredentials only lists this user\'s validated credentials', async () => {
    const mine = await enrolled('log-2');
    await enrolled('log-2-other');
    const options = await loginChallenge('log-2');
    assert.deepEqual(options.allowCredentials.map((c) => c.id), [mine.id]);
    assert.equal(options.userVerification, 'required');
    assert.equal(options.rpId, require('./fixtures.cjs').config.rpID);
    const stored = h.store().webauthnChallenges.find((c) => c.challenge === options.challenge);
    assert.equal(stored.purpose, 'authentication');
    assert.equal(stored.userId, 'log-2');
    assert.equal((await passkeys.loginOptions({}, {}, h.client)).status, 401);
});

test('valid assertion logs in: signed session with auth_time + amr webauthn, counter persisted, audited', async () => {
    const device = await enrolled('log-3');
    const options = await loginChallenge('log-3');
    const r = await users.verifyPasskey(h.preAuth('log-3'), {
        challenge: options.challenge,
        response: device.assert(options.challenge, { counter: 5, userHandle: handle('log-3') }),
    }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const claims = h.decodeJwt(r.data.token);
    assert.equal(claims.isAuthorized, true);
    assert.equal(claims.uuid, 'log-3');
    assert.ok(Number.isSafeInteger(claims.auth_time));
    assert.deepEqual(claims.amr, ['webauthn']);
    assert.equal(h.credentials().find((c) => c.credentialId === device.id).counter, 5);
    assert.ok(h.auditActions('log-3').includes('login'));
});

test('replaying the same assertion fails (challenge consumed)', async () => {
    const device = await enrolled('log-4');
    const options = await loginChallenge('log-4');
    const body = { challenge: options.challenge, response: device.assert(options.challenge, { counter: 1 }) };
    assert.equal((await users.verifyPasskey(h.preAuth('log-4'), body, h.client)).status, 200);
    const replay = await users.verifyPasskey(h.preAuth('log-4'), body, h.client);
    assert.equal(replay.status, 401);
    assert.equal(replay.data.token, undefined);
});

test('sign count that does not increase is treated as a cloned authenticator', async () => {
    const device = await enrolled('log-5');
    let options = await loginChallenge('log-5');
    assert.equal((await users.verifyPasskey(h.preAuth('log-5'), { challenge: options.challenge, response: device.assert(options.challenge, { counter: 10 }) }, h.client)).status, 200);
    for (const counter of [10, 3]) {
        options = await loginChallenge('log-5');
        const r = await users.verifyPasskey(h.preAuth('log-5'), { challenge: options.challenge, response: device.assert(options.challenge, { counter }) }, h.client);
        assert.equal(r.status, 401);
    }
    assert.equal(h.credentials().find((c) => c.credentialId === device.id).counter, 10);
    assert.ok(h.auditActions('log-5').includes('passkey_clone_suspected'));
});

test('a credential enrolled by another user cannot log in as this user', async () => {
    const theirs = await enrolled('log-6-owner');
    h.seedUser('log-6-victim');
    const options = await loginChallenge('log-6-victim');
    const r = await users.verifyPasskey(h.preAuth('log-6-victim'), { challenge: options.challenge, response: theirs.assert(options.challenge) }, h.client);
    assert.equal(r.status, 403);
    assert.equal(r.data.token, undefined);
});

test('legacy unvalidated passkeys keep failing with the re-enrollment 403', async () => {
    const legacy = authenticator();
    h.seedUser('log-7', { legacyPasskeys: [{ passkey: { id: legacy.id } }] });
    const options = await loginChallenge('log-7');
    assert.deepEqual(options.allowCredentials, []);
    const r = await users.verifyPasskey(h.preAuth('log-7'), { challenge: options.challenge, response: legacy.assert(options.challenge) }, h.client);
    assert.equal(r.status, 403);
    assert.equal(r.data.error.message, 'Passkey re-enrollment required');
    assert.match(r.data.error.reason, /password.*re-enroll/i);
    // legacy identifier-only payload shape
    const old = await users.verifyPasskey(h.preAuth('log-7'), { passkey: { id: legacy.id } }, h.client);
    assert.equal(old.status, 403);
    assert.equal(old.data.error.message, 'Passkey re-enrollment required');
});

for (const [name, opts, extra] of [
    ['wrong origin', { origin: 'https://evil.example.invalid' }],
    ['wrong rpID', { rpID: 'evil.example.invalid' }],
    ['tampered signature', { tamper: true }],
    ['missing user verification', { flags: 1 }],
    ['wrong userHandle', { userHandle: b64(Buffer.from('someone-else')) }],
]) {
    test(`assertion with ${name} is rejected (401), no session, counter unchanged`, async () => {
        const uuid = 'log-8-' + name.replace(/\W/g, '');
        const device = await enrolled(uuid);
        const options = await loginChallenge(uuid);
        const r = await users.verifyPasskey(h.preAuth(uuid), { challenge: options.challenge, response: device.assert(options.challenge, opts) }, h.client);
        assert.equal(r.status, 401, JSON.stringify(r.data));
        assert.equal(r.data.token, undefined);
        assert.equal(h.credentials().find((c) => c.credentialId === device.id).counter, 0);
    });
}

test('challenge from another user or for registration cannot be used to log in', async () => {
    const device = await enrolled('log-9');
    await enrolled('log-9b');
    const foreign = await loginChallenge('log-9b');
    let r = await users.verifyPasskey(h.preAuth('log-9'), { challenge: foreign.challenge, response: device.assert(foreign.challenge) }, h.client);
    assert.equal(r.status, 401);
    const reg = (await passkeys.enrollmentOptions(h.strong('log-9'), {}, h.client)).data;
    r = await users.verifyPasskey(h.preAuth('log-9'), { challenge: reg.challenge, response: device.assert(reg.challenge) }, h.client);
    assert.equal(r.status, 401);
});

test('PRF output in a login payload is refused before verification', async () => {
    const device = await enrolled('log-10');
    const options = await loginChallenge('log-10');
    const r = await users.verifyPasskey(h.preAuth('log-10'), {
        challenge: options.challenge,
        response: device.assert(options.challenge, { extensions: { prf: { results: { first: 'secret' } } } }),
    }, h.client);
    assert.equal(r.status, 400);
    assert.match(r.data.error.reason, /PRF/);
    assert.equal((await passkeys.loginOptions(h.preAuth('log-10'), { prf: {} }, h.client)).status, 400);
});

test('passkey login is rate limited per user', async () => {
    const device = await enrolled('log-rl');
    let last;
    for (let i = 0; i <= limiter.LIMITS.LOGIN_PER_WINDOW; i++) {
        last = await users.verifyPasskey(h.preAuth('log-rl'), { challenge: 'A'.repeat(43), response: device.assert('A'.repeat(43)) }, h.client);
    }
    assert.equal(last.status, 429);
    // A flooded login budget (pre-auth, attacker-reachable) does not starve
    // the victim's authenticated enrollment / unlock budget.
    assert.equal((await passkeys.enrollmentOptions(h.strong('log-rl'), {}, h.client)).status, 200);
});

test('Netlify users function routes passkey login', async () => {
    const device = await enrolled('log-nf');
    const headers = h.preAuth('log-nf');
    let r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/users/login/passkey/options', headers, body: '{}' });
    assert.equal(r.statusCode, 200, r.body);
    const { challenge } = JSON.parse(r.body);
    r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/users/login/passkey', headers, body: JSON.stringify({ challenge, response: device.assert(challenge, { counter: 2 }) }) });
    assert.equal(r.statusCode, 200, r.body);
    assert.ok(JSON.parse(r.body).token);
});
