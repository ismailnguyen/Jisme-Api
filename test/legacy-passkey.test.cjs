'use strict';
// Legacy passkeys (users.passkeys written by the previous client). The old
// identifier-only login is gone for good: it never checked a signature. Entries
// that still carry their create() attestation are verified cryptographically and
// promoted into the credential store on first use; the rest fall back to password.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const h = require('./helpers-auth.cjs');
const { authenticator, b64 } = require('./fixtures.cjs');

const users = require('../controllers/userController.js');
const passkeys = require('../controllers/passkeyController.js');

const source = fs.readFileSync(path.join(__dirname, '../services/userService.js'), 'utf8');
test('legacy identifier-only service call cannot mint a login; clear recovery path', async () => {
    const start = source.indexOf('const verifyPasskey = async function(');
    const end = source.indexOf('\nconst login = async function(', start);
    let authenticated = false;
    const context = vm.createContext({ encrypt: x => x, decrypt: x => x, findUser: async () => ({ uuid: 'owner', email: 'e', passkeys: [{ passkey: { id: 'credential' } }] }), login: async () => { authenticated = true; }, generateError: (message, reason, code) => Object.assign(new Error(reason), { code }) });
    vm.runInContext(source.slice(start, end) + '\nthis.verifyPasskey=verifyPasskey;', context);
    await assert.rejects(context.verifyPasskey('credential', 'owner', false, {}), /password.*re-enroll/i);
    assert.equal(authenticated, false);
});

// What the previous client stored: { deviceName, passkey: <webauthn-json create() JSON> }.
const legacyEntry = (device, deviceName = 'Old phone') => ({
    deviceName,
    passkey: device.register(b64(Buffer.from('legacy-client-challenge')), { flags: 1, transports: ['internal', 'hybrid'] }),
});

test('legacy entry without attestation keeps the password step and the re-enrollment 403', async () => {
    h.seedUser('leg-0', { legacyPasskeys: [{ passkey: { id: 'opaque' } }] });
    const r = await users.login({ email: h.email('leg-0') }, h.client);
    assert.equal(r.data.next.step, 'verify_password');
    assert.equal(r.data.hasPasskey, false);
});

test('legacy entry with attestation: passkey-first login, verified by signature, promoted to the store', async () => {
    const device = authenticator();
    h.seedUser('leg-1', { mfa: true, legacyPasskeys: [legacyEntry(device)] });

    const login = await users.login({ email: h.email('leg-1') }, h.client);
    assert.equal(login.status, 200, JSON.stringify(login.data));
    assert.deepEqual(login.data.next, { step: 'verify_passkey', url: '/login/passkey' });
    assert.equal(login.data.hasPasskey, true);
    assert.deepEqual(login.data.passkeys, [{ id: device.id, verified: false, name: 'Old phone' }]);
    const bearer = { authorization: 'Bearer ' + login.data.token };

    const options = await passkeys.loginOptions(bearer, {}, h.client);
    assert.equal(options.status, 200, JSON.stringify(options.data));
    assert.deepEqual(options.data.allowCredentials, [{ id: device.id, type: 'public-key', transports: ['internal', 'hybrid'] }]);
    assert.equal(options.data.userVerification, 'preferred');

    // Forged signature is refused even for a legacy passkey.
    const forged = await users.verifyPasskey(bearer, { challenge: options.data.challenge, response: device.assert(options.data.challenge, { flags: 1, userHandle: 'leg-1', tamper: true }) }, h.client);
    assert.equal(forged.status, 401, JSON.stringify(forged.data));
    assert.equal(h.credentials().length, 0);

    const again = (await passkeys.loginOptions(bearer, {}, h.client)).data;
    // No UV flag (enrolled with 'preferred'); userHandle echoes the uuid string as the old client set it.
    const r = await users.verifyPasskey(bearer, { challenge: again.challenge, response: device.assert(again.challenge, { flags: 1, counter: 1, userHandle: 'leg-1' }) }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const claims = h.decodeJwt(r.data.token);
    assert.equal(claims.isAuthorized, true);
    assert.deepEqual(claims.amr, ['webauthn']);

    const stored = h.credentials().find((c) => c.credentialId === device.id);
    assert.ok(stored, 'promoted into the credential store');
    assert.equal(stored.legacy, true);
    assert.equal(stored.counter, 1);
    assert.equal(stored.name, 'Old phone');
    assert.equal(h.userDoc('leg-1').hasVerifiedPasskey, true);
    assert.deepEqual(h.userDoc('leg-1').passkeys.length, 1, 'users.passkeys left untouched');
    assert.ok(h.auditActions('leg-1').includes('passkey_migrated'));
    assert.deepEqual(r.data.passkeys, [{ id: device.id, verified: true, name: 'Old phone', createdAt: stored.createdAt, transports: ['internal', 'hybrid'] }]);

    // Second login goes through the store: counter must advance.
    const third = (await passkeys.loginOptions(bearer, {}, h.client)).data;
    assert.deepEqual(third.allowCredentials.map((c) => c.id), [device.id]);
    const replay = await users.verifyPasskey(bearer, { challenge: third.challenge, response: device.assert(third.challenge, { flags: 1, counter: 1, userHandle: 'leg-1' }) }, h.client);
    assert.equal(replay.status, 401, JSON.stringify(replay.data));
    const fourth = (await passkeys.loginOptions(bearer, {}, h.client)).data;
    const ok = await users.verifyPasskey(bearer, { challenge: fourth.challenge, response: device.assert(fourth.challenge, { flags: 1, counter: 2, userHandle: 'leg-1' }) }, h.client);
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
});

test('legacy entry whose attestation does not match its id is ignored', async () => {
    const device = authenticator();
    const entry = legacyEntry(device);
    entry.passkey.id = 'someone-elses-id';
    h.seedUser('leg-2', { legacyPasskeys: [entry] });
    const r = await users.login({ email: h.email('leg-2') }, h.client);
    assert.equal(r.data.hasPasskey, false);
    assert.deepEqual((await passkeys.loginOptions({ authorization: 'Bearer ' + r.data.token }, {}, h.client)).data.allowCredentials, []);
});

test('generic update ignores client-supplied passkeys', async () => {
    h.seedUser('leg-3');
    const r = await users.update(h.strong('leg-3'), { passkeys: [{ id: 'x' }] });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(h.userDoc('leg-3').passkeys, undefined);
});

// Sessions minted before auth_time/amr existed (up to 90 days) keep working:
// read + password-confirmed delete are allowed, enrollment asks to sign in again.
test('legacy session token (no auth_time/amr) is still an authenticated password session', async () => {
    h.seedUser('leg-4', { legacyPasskeys: [{ deviceName: 'Old', passkey: { id: 'old-id' } }] });
    const legacy = h.bearer({ uuid: 'leg-4', email: h.email('leg-4'), step: 'loggedIn', isAuthorized: true });
    const list = await passkeys.list(legacy);
    assert.equal(list.status, 200, JSON.stringify(list.data));
    assert.deepEqual(list.data.passkeys.map((p) => p.id), ['old-id']);
    const options = await passkeys.enrollmentOptions(legacy, {}, h.client);
    assert.equal(options.status, 401);
    assert.equal(options.data.error.message, 'Reauthentication required');
    const removed = await passkeys.remove(legacy, { id: 'old-id' }, { password: 'correct horse battery' }, h.client);
    assert.equal(removed.status, 200, JSON.stringify(removed.data));
    assert.deepEqual(h.userDoc('leg-4').passkeys, []);
});
