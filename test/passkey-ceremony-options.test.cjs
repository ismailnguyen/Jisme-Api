'use strict';
// WebAuthn ceremony options.
// - registration: preferredAuthenticatorType 'localDevice' → the real
//   @simplewebauthn/server output carries hints ['client-device'] and
//   authenticatorSelection.authenticatorAttachment 'platform'; residentKey 'required'.
// - authentication: allowCredentials carry the transports the credential was
//   stored with (the browser decides: platform, USB key, hybrid/QR), as before.
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

test('registration options: local device preferred (platform attachment, client-device hint, resident key required)', async () => {
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

test('authentication options: allowCredentials keep the stored transports', async () => {
    h.seedUser('pco-2');
    const hybrid = await enrollWith('pco-2', ['hybrid']);
    const mixed = await enrollWith('pco-2', ['cable', 'usb', 'internal']);

    const r = await passkeys.loginOptions(h.preAuth('pco-2'), {}, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const byId = Object.fromEntries(r.data.allowCredentials.map((c) => [c.id, c.transports]));
    assert.deepEqual(byId[hybrid.id], ['hybrid']);
    assert.deepEqual(byId[mixed.id], ['cable', 'usb', 'internal']);
    assert.equal(r.data.userVerification, 'required');
});
