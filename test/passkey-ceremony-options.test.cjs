'use strict';
// WebAuthn ceremonies are restricted to the local device (Face ID / Touch ID /
// Windows Hello): no hybrid QR / external password-manager flow on iOS.
// - registration: preferredAuthenticatorType 'localDevice' → the real
//   @simplewebauthn/server output carries hints ['client-device'] and
//   authenticatorSelection.authenticatorAttachment 'platform'; residentKey 'required'.
// - authentication: every allowCredentials entry is pinned to ['internal'],
//   whatever transports the stored credential declared.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');

async function enrollWith(uuid, transports) {
    const headers = h.strong(uuid);
    const options = await passkeys.enrollmentOptions(headers, {}, h.client);
    assert.equal(options.status, 200, JSON.stringify(options.data));
    const device = authenticator();
    const response = device.register(options.data.challenge, { transports });
    const result = await passkeys.enroll(headers, { challenge: options.data.challenge, response }, h.client);
    assert.equal(result.status, 201, JSON.stringify(result.data));
    return device;
}

test('registration options: local device only (platform attachment, client-device hint, resident key required)', async () => {
    h.seedUser('pco-1');
    const r = await passkeys.enrollmentOptions(h.strong('pco-1'), {}, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(r.data.hints, ['client-device']);
    assert.deepEqual(r.data.authenticatorSelection, {
        residentKey: 'required',
        userVerification: 'required',
        requireResidentKey: true,
        authenticatorAttachment: 'platform',
    });
});

test('authentication options: allowCredentials transports pinned to ["internal"] even if stored as hybrid', async () => {
    h.seedUser('pco-2');
    const hybrid = await enrollWith('pco-2', ['hybrid']);
    const mixed = await enrollWith('pco-2', ['cable', 'usb', 'internal']);
    const stored = h.credentials().find((c) => c.credentialId === hybrid.id);
    assert.deepEqual(stored.transports, ['hybrid'], 'stored transports are left untouched');

    const r = await passkeys.loginOptions(h.preAuth('pco-2'), {}, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const allowed = r.data.allowCredentials;
    assert.deepEqual(allowed.map((c) => c.id).sort(), [hybrid.id, mixed.id].sort());
    for (const c of allowed) assert.deepEqual(c.transports, ['internal'], c.id);
});
