'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator } = require('./fixtures.cjs');
const passkeys = require('../controllers/passkeyController.js');
const users = require('../controllers/userController.js');
const netlify = require('../netlify/functions/users/index.js');

async function login(uuid) {
    const result = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/users/login',
        headers: {}, body: JSON.stringify({ email: h.email(uuid) }) });
    assert.equal(result.statusCode, 200, result.body);
    return JSON.parse(result.body);
}

test('user payloads merge verified credentials without changing legacy storage or leaking internals', async () => {
    const uuid = 'payload-owner';
    const legacy = { deviceName: 'Old phone', passkey: { id: 'legacy-id', publicKey: 'never-expose' } };
    h.seedUser(uuid, { legacyPasskeys: [legacy] });
    h.seedUser('payload-other');
    const device = authenticator();
    const options = await passkeys.enrollmentOptions(h.strong(uuid), {}, h.client);
    const enrolled = await passkeys.enroll(h.strong(uuid), {
        challenge: options.data.challenge, response: device.register(options.data.challenge),
    }, h.client);
    assert.equal(enrolled.status, 201);
    const collision = { id: device.id, publicKey: 'legacy-internals' };
    h.userDoc(uuid).passkeys.push(collision);
    const expected = [
        { id: device.id, transports: ['internal'], createdAt: enrolled.data.createdAt, verified: true },
        { id: 'legacy-id', name: 'Old phone', verified: false },
    ];
    const check = (payload) => {
        assert.deepEqual(payload.passkeys, expected);
        for (const entry of payload.passkeys) {
            assert.ok(Object.keys(entry).every(key => ['id', 'name', 'createdAt', 'verified', 'transports'].includes(key)));
        }
        assert.doesNotMatch(JSON.stringify(payload.passkeys), /publicKey|counter|never-expose/);
    };
    check(await login(uuid));
    const password = await users.verifyPassword(h.preAuth(uuid), { password: 'correct horse battery' }, h.client);
    assert.equal(password.status, 200, JSON.stringify(password.data));
    check(password.data);
    const info = await users.getInformation(h.strong(uuid));
    assert.equal(info.status, 200);
    check(info.data);
    const updated = await users.update(h.strong(uuid), { avatarUrl: 'avatar' });
    assert.equal(updated.status, 200);
    check(updated.data);
    assert.deepEqual(h.userDoc(uuid).passkeys, [legacy, collision]);
    assert.deepEqual((await login('payload-other')).passkeys, []);
    const removed = await passkeys.remove(h.strong(uuid), { id: device.id }, { password: 'correct horse battery' }, h.client);
    assert.equal(removed.status, 200);
    const after = await login(uuid);
    assert.equal(after.passkeys.some(p => p.verified), false);
    assert.equal(after.passkeys.filter(p => p.id === device.id).length, 1);
    assert.deepEqual((await users.getInformation(h.strong(uuid))).data.passkeys, after.passkeys);
});

test('password verification requiring OTP includes the merged passkeys', async () => {
    const uuid = 'payload-mfa';
    h.seedUser(uuid, { mfa: true, legacyPasskeys: [{ credentialId: 'old-mfa' }] });
    const device = authenticator();
    const options = await passkeys.enrollmentOptions(h.strong(uuid, { amr: ['pwd', 'otp'] }), {}, h.client);
    const enrolled = await passkeys.enroll(h.strong(uuid, { amr: ['pwd', 'otp'] }), {
        challenge: options.data.challenge, response: device.register(options.data.challenge),
    }, h.client);
    assert.equal(enrolled.status, 201);
    const result = await users.verifyPassword(h.preAuth(uuid), { password: 'correct horse battery' }, h.client);
    assert.equal(result.status, 200);
    assert.equal(result.data.next.step, 'verify_otp');
    assert.equal(result.data.passkeys[0].id, device.id);
    assert.equal(result.data.passkeys[0].verified, true);
    assert.deepEqual(result.data.passkeys[1], { id: 'old-mfa', verified: false });
    const otp = require('otplib').authenticator.generate('JBSWY3DPEHPK3PXP');
    const verified = await users.verifyOTP({ authorization: 'Bearer ' + result.data.token }, { totpToken: otp }, h.client);
    assert.equal(verified.status, 200, JSON.stringify(verified.data));
    assert.deepEqual(verified.data.passkeys, result.data.passkeys);
    const removed = await passkeys.remove(h.strong(uuid, { amr: ['pwd', 'otp'] }), { id: device.id },
        { password: 'correct horse battery' }, h.client);
    assert.equal(removed.status, 200);
    assert.deepEqual((await login(uuid)).passkeys, [{ id: 'old-mfa', verified: false }]);
    assert.deepEqual((await users.getInformation(h.strong(uuid))).data.passkeys, [{ id: 'old-mfa', verified: false }]);
});
