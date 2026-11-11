'use strict';
// Passkey-first login routing (original behaviour restored): a user with a
// verified passkey is sent straight to the passkey ceremony at email entry;
// everyone else (incl. legacy unverified passkeys) stays on the password step.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator, b64 } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');
const users = require('../controllers/userController.js');

async function enrolled(uuid, opts) {
    h.seedUser(uuid, opts);
    const device = authenticator();
    const session = h.strong(uuid, { amr: ['pwd', 'otp'] });
    const options = (await passkeys.enrollmentOptions(session, {}, h.client)).data;
    const r = await passkeys.enroll(session, { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 201, JSON.stringify(r.data));
    return device;
}

const bearer = (token) => ({ authorization: 'Bearer ' + token });

test('verified passkey user is routed straight to the passkey ceremony', async () => {
    const device = await enrolled('pkf-1', { mfa: true });
    const r = await users.login({ email: h.email('pkf-1') }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(r.data.email, h.email('pkf-1'));
    assert.deepEqual(r.data.next, { step: 'verify_passkey', url: '/login/passkey' });
    assert.equal(r.data.isPasswordRequired, false);
    assert.equal(r.data.isOtpRequired, true);
    assert.equal(r.data.hasPasskey, true);
    assert.ok(Array.isArray(r.data.passkeys));
    assert.deepEqual(r.data.passkeys.map((p) => [p.id, p.verified]), [[device.id, true]]);
    const claims = h.decodeJwt(r.data.token);
    assert.equal(claims.step, 'request_passkey');
    assert.equal(claims.uuid, 'pkf-1');
    assert.equal(claims.isAuthorized, false);
});

test('user without a verified passkey keeps the password step (unchanged)', async () => {
    h.seedUser('pkf-2');
    h.seedUser('pkf-2-legacy', { legacyPasskeys: [{ passkey: { id: 'legacy-cred' } }] });
    for (const uuid of ['pkf-2', 'pkf-2-legacy']) {
        const r = await users.login({ email: h.email(uuid) }, h.client);
        assert.equal(r.status, 200);
        assert.deepEqual(r.data.next, { step: 'verify_password', url: '/login/password' });
        assert.equal(r.data.isPasswordRequired, true);
        assert.equal(r.data.hasPasskey, false);
        assert.equal(h.decodeJwt(r.data.token).step, 'request_password');
    }
});

test('unknown user still gets the unchanged fake password response', async () => {
    const r = await users.login({ email: 'nobody-pkf@example.invalid' }, h.client);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.next, { step: 'verify_password', url: '/login/password' });
    assert.equal(r.data.isPasswordRequired, true);
    assert.equal(r.data.hasPasskey, false);
    assert.equal(r.data.passkeys, undefined);
    assert.equal(h.decodeJwt(r.data.token).uuid, '00000000-0000-0000-0000-000000000000');
});

test('request_passkey token drives passkey options + login, and still allows password fallback', async () => {
    const device = await enrolled('pkf-4');
    const { token } = (await users.login({ email: h.email('pkf-4') }, h.client)).data;
    assert.equal(h.decodeJwt(token).step, 'request_passkey');
    const options = await passkeys.loginOptions(bearer(token), {}, h.client);
    assert.equal(options.status, 200, JSON.stringify(options.data));
    assert.deepEqual(options.data.allowCredentials.map((c) => c.id), [device.id]);
    const r = await users.verifyPasskey(bearer(token), {
        challenge: options.data.challenge,
        response: device.assert(options.data.challenge, { counter: 1, userHandle: b64(Buffer.from('pkf-4')) }),
    }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(h.decodeJwt(r.data.token).isAuthorized, true);
    // "Use password instead" from the passkey screen keeps working.
    const pwd = await users.verifyPassword(bearer(token), { password: 'correct horse battery' }, h.client);
    assert.equal(pwd.status, 200, JSON.stringify(pwd.data));
});
