'use strict';
// P1 verified passkey enrollment: registration ceremony bound to a fresh
// password(+MFA) session, server-side challenge (2 min, single use, user bound),
// cryptographic verifyRegistrationResponse, validated credential storage,
// password-confirmed deletion, audit log and rate limiting.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator, config, b64 } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');
const users = require('../controllers/userController.js');
const limiter = require('../services/vaultRateLimit.js');
const netlify = require('../netlify/functions/users/index.js');

async function enroll(uuid, device = authenticator(), headers = h.strong(uuid)) {
    const options = await passkeys.enrollmentOptions(headers, {}, h.client);
    assert.equal(options.status, 200, JSON.stringify(options.data));
    const response = device.register(options.data.challenge);
    const result = await passkeys.enroll(headers, { challenge: options.data.challenge, response }, h.client);
    return { device, options: options.data, result, response };
}

test('registration options: rp/user binding, UV required, challenge stored server-side for ~2 min', async () => {
    h.seedUser('enr-1');
    const before = Date.now();
    const r = await passkeys.enrollmentOptions(h.strong('enr-1'), {}, h.client);
    assert.equal(r.status, 200);
    assert.equal(r.data.rp.id, config.rpID);
    assert.equal(r.data.user.id, b64(Buffer.from('enr-1')));
    assert.equal(r.data.authenticatorSelection.userVerification, 'required');
    assert.match(r.data.challenge, /^[A-Za-z0-9_-]{43}$/);
    const stored = h.store().webauthnChallenges.find((c) => c.challenge === r.data.challenge);
    assert.ok(stored, 'challenge must be stored server-side');
    assert.equal(stored.userId, 'enr-1');
    assert.equal(stored.purpose, 'registration');
    assert.ok(stored.expiresAt - before <= 125000 && stored.expiresAt - before >= 115000, 'TTL ~2 minutes');
    assert.doesNotMatch(JSON.stringify(r.data), /prf/i);
});

const rejectedSessions = {
    'no session': () => ({}),
    'pre-auth token': () => h.preAuth('enr-2'),
    'stale auth_time (> 5 min)': () => h.strong('enr-2', { authTime: h.nowS() - 301 }),
    'future auth_time': () => h.strong('enr-2', { authTime: h.nowS() + 120 }),
    'legacy token without amr': () => h.bearer({ uuid: 'enr-2', isAuthorized: true, auth_time: h.nowS() }),
    'passkey-only session (no password)': () => h.strong('enr-2', { amr: ['webauthn'] }),
    'wrong signing secret': () => h.bearer({ uuid: 'enr-2', isAuthorized: true, auth_time: h.nowS(), amr: ['pwd'] }, 'other'),
};
for (const [name, headers] of Object.entries(rejectedSessions)) {
    test(`enrollment refuses ${name} with 401 and issues no challenge`, async () => {
        h.seedUser('enr-2');
        const before = h.store().webauthnChallenges.length;
        const r = await passkeys.enrollmentOptions(headers(), {}, h.client);
        assert.equal(r.status, 401);
        const v = await passkeys.enroll(headers(), { challenge: 'x'.repeat(43), response: {} }, h.client);
        assert.equal(v.status, 401);
        assert.equal(h.store().webauthnChallenges.length, before);
    });
}

test('MFA user needs password AND otp in the session', async () => {
    h.seedUser('enr-mfa', { mfa: true });
    assert.equal((await passkeys.enrollmentOptions(h.strong('enr-mfa', { amr: ['pwd'] }), {}, h.client)).status, 401);
    assert.equal((await passkeys.enrollmentOptions(h.strong('enr-mfa', { amr: ['pwd', 'otp'] }), {}, h.client)).status, 200);
});

test('verified enrollment persists id, validated public key, counter, transports; audit logged', async () => {
    h.seedUser('enr-3');
    const { device, result } = await enroll('enr-3');
    assert.equal(result.status, 201, JSON.stringify(result.data));
    assert.equal(result.data.id, device.id);
    assert.deepEqual(result.data.transports, ['internal']);
    const doc = h.credentials().find((c) => c.credentialId === device.id);
    assert.ok(doc, 'credential stored');
    assert.equal(doc.validated, true);
    assert.equal(doc.counter, 0);
    assert.match(doc.publicKey, /^[A-Za-z0-9_-]+$/);
    assert.deepEqual(doc.transports, ['internal']);
    assert.doesNotMatch(JSON.stringify(doc), /enr-3/, 'raw uuid is not stored with the credential');
    assert.equal(h.userDoc('enr-3').hasVerifiedPasskey, true);
    assert.ok(h.auditActions('enr-3').includes('passkey_enrolled'));
});

test('transports are allowlisted', async () => {
    h.seedUser('enr-tr');
    const device = authenticator();
    const options = (await passkeys.enrollmentOptions(h.strong('enr-tr'), {}, h.client)).data;
    const response = device.register(options.challenge, { transports: ['usb', '<script>', 'internal', 'usb'] });
    const r = await passkeys.enroll(h.strong('enr-tr'), { challenge: options.challenge, response }, h.client);
    assert.equal(r.status, 201);
    assert.deepEqual(r.data.transports, ['usb', 'internal']);
});

test('challenge is single use: replaying the same registration fails', async () => {
    h.seedUser('enr-4');
    const { options, response, result } = await enroll('enr-4');
    assert.equal(result.status, 201);
    const replay = await passkeys.enroll(h.strong('enr-4'), { challenge: options.challenge, response }, h.client);
    assert.equal(replay.status, 400);
    assert.equal(h.credentials().filter((c) => c.credentialId === response.id).length, 1);
});

test('challenge is bound to the user that requested it', async () => {
    h.seedUser('enr-5a'); h.seedUser('enr-5b');
    const options = (await passkeys.enrollmentOptions(h.strong('enr-5a'), {}, h.client)).data;
    const device = authenticator();
    const r = await passkeys.enroll(h.strong('enr-5b'), { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 400);
    assert.equal(h.credentials().some((c) => c.credentialId === device.id), false);
});

test('expired challenge (> 2 min) is refused', async () => {
    h.seedUser('enr-6');
    const options = (await passkeys.enrollmentOptions(h.strong('enr-6'), {}, h.client)).data;
    h.store().webauthnChallenges.find((c) => c.challenge === options.challenge).expiresAt = Date.now() - 1;
    const r = await passkeys.enroll(h.strong('enr-6'), { challenge: options.challenge, response: authenticator().register(options.challenge) }, h.client);
    assert.equal(r.status, 400);
});

for (const [name, opts] of [
    ['wrong origin', { origin: 'https://evil.example.invalid' }],
    ['wrong rpID', { rpID: 'evil.example.invalid' }],
    ['no user verification flag', { flags: 1 }],
]) {
    test(`cryptographic verification rejects ${name}; nothing stored`, async () => {
        h.seedUser('enr-7');
        const options = (await passkeys.enrollmentOptions(h.strong('enr-7'), {}, h.client)).data;
        const device = authenticator();
        const r = await passkeys.enroll(h.strong('enr-7'), { challenge: options.challenge, response: device.register(options.challenge, opts) }, h.client);
        assert.equal(r.status, 400);
        assert.equal(h.credentials().some((c) => c.credentialId === device.id), false);
    });
}

test('PRF material in the enrollment payload is refused (400) and nothing stored', async () => {
    h.seedUser('enr-8');
    const options = (await passkeys.enrollmentOptions(h.strong('enr-8'), {}, h.client)).data;
    const device = authenticator();
    const response = device.register(options.challenge, { extensions: { prf: { enabled: true, results: { first: 'secret' } } } });
    const r = await passkeys.enroll(h.strong('enr-8'), { challenge: options.challenge, response }, h.client);
    assert.equal(r.status, 400);
    assert.match(r.data.error.reason, /PRF/);
    assert.doesNotMatch(JSON.stringify(r.data), /secret/);
    assert.equal(h.credentials().some((c) => c.credentialId === device.id), false);
    assert.equal((await passkeys.enrollmentOptions(h.strong('enr-8'), { prfSalt: 'x' }, h.client)).status, 400);
});

test('re-registering an existing credential id is a 409; options exclude enrolled credentials', async () => {
    h.seedUser('enr-9');
    const { device } = await enroll('enr-9');
    const options = (await passkeys.enrollmentOptions(h.strong('enr-9'), {}, h.client)).data;
    assert.deepEqual(options.excludeCredentials.map((c) => c.id), [device.id]);
    const r = await passkeys.enroll(h.strong('enr-9'), { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 409);
});

test('PUT /users ignores a client-supplied passkeys array (previous client still sends it)', async () => {
    h.seedUser('enr-10', { legacyPasskeys: [{ passkey: { id: 'keep' } }] });
    const r = await users.update(h.strong('enr-10'), { passkeys: [{ id: 'x', publicKey: 'y', validated: true }] });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(h.userDoc('enr-10').passkeys, [{ passkey: { id: 'keep' } }]);
});

test('list returns only the caller\'s validated passkeys, never public keys', async () => {
    h.seedUser('enr-11a'); h.seedUser('enr-11b');
    const a = await enroll('enr-11a');
    await enroll('enr-11b');
    const r = await passkeys.list(h.strong('enr-11a', { authTime: h.nowS() - 3600 }));
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.passkeys.map((p) => p.id), [a.device.id]);
    assert.doesNotMatch(JSON.stringify(r.data), /publicKey/);
});

test('DELETE requires a password session plus current password; audited', async () => {
    h.seedUser('enr-12', { password: 'pw-12' });
    h.seedUser('enr-12x');
    const { device } = await enroll('enr-12');
    const params = { id: device.id };
    // missing / wrong password
    assert.equal((await passkeys.remove(h.strong('enr-12'), params, {}, h.client)).status, 400);
    const wrong = await passkeys.remove(h.strong('enr-12'), params, { password: 'nope' }, h.client);
    assert.equal(wrong.status, 401);
    assert.ok(h.auditActions('enr-12').includes('passkey_delete_failed'));
    // pre-auth and passkey-only sessions
    assert.equal((await passkeys.remove(h.preAuth('enr-12'), params, { password: 'pw-12' }, h.client)).status, 401);
    assert.equal((await passkeys.remove(h.strong('enr-12', { amr: ['webauthn'] }), params, { password: 'pw-12' }, h.client)).status, 401);
    // another user cannot delete it, even with their own password
    assert.equal((await passkeys.remove(h.strong('enr-12x'), params, { password: 'correct horse battery' }, h.client)).status, 404);
    assert.ok(h.credentials().some((c) => c.credentialId === device.id));
    // success (older password session is fine: the password itself is re-confirmed)
    const ok = await passkeys.remove(h.strong('enr-12', { authTime: h.nowS() - 3600 }), params, { password: 'pw-12' }, h.client);
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.data, { id: device.id, deleted: true });
    assert.equal(h.credentials().some((c) => c.credentialId === device.id), false);
    assert.equal(h.userDoc('enr-12').hasVerifiedPasskey, false);
    assert.ok(h.auditActions('enr-12').includes('passkey_deleted'));
    assert.equal((await passkeys.remove(h.strong('enr-12'), params, { password: 'pw-12' }, h.client)).status, 404);
});

test('enrollment endpoints are rate limited per user (429 + Retry-After)', async () => {
    h.seedUser('enr-rl');
    let last;
    for (let i = 0; i <= limiter.LIMITS.SENSITIVE_PER_WINDOW; i++) {
        last = await passkeys.enrollmentOptions(h.strong('enr-rl'), {}, h.client);
    }
    assert.equal(last.status, 429);
    assert.ok(Number(last.headers['Retry-After']) >= 1);
    // another user is unaffected
    h.seedUser('enr-rl2');
    assert.equal((await passkeys.enrollmentOptions(h.strong('enr-rl2'), {}, h.client)).status, 200);
});

test('Netlify users function routes the enrollment endpoints', async () => {
    h.seedUser('enr-nf');
    const headers = h.strong('enr-nf');
    const ev = (httpMethod, path, body) => ({ httpMethod, path, headers, body: body === undefined ? null : JSON.stringify(body) });
    let r = await netlify.handler(ev('POST', '/.netlify/functions/users/passkeys/options', {}));
    assert.equal(r.statusCode, 200, r.body);
    const options = JSON.parse(r.body);
    const device = authenticator();
    r = await netlify.handler(ev('POST', '/.netlify/functions/users/passkeys', { challenge: options.challenge, response: device.register(options.challenge) }));
    assert.equal(r.statusCode, 201, r.body);
    r = await netlify.handler(ev('GET', '/.netlify/functions/users/passkeys'));
    assert.equal(r.statusCode, 200);
    assert.equal(JSON.parse(r.body).passkeys.length, 1);
    r = await netlify.handler(ev('DELETE', '/.netlify/functions/users/passkeys/' + device.id, { password: 'correct horse battery' }));
    assert.equal(r.statusCode, 200, r.body);
    r = await netlify.handler({ ...ev('POST', '/.netlify/functions/users/passkeys'), body: '{bad' });
    assert.equal(r.statusCode, 400);
});

test('Express user routes mount the enrollment endpoints', () => {
    const routes = [];
    const app = { route: (path) => { const r = {}; for (const m of ['get', 'post', 'put', 'delete']) r[m] = () => { routes.push(m.toUpperCase() + ' ' + path); return r; }; return r; } };
    require('../server/routes/userRoutes.js')(app);
    for (const route of ['POST /users/passkeys/options', 'POST /users/passkeys', 'GET /users/passkeys', 'DELETE /users/passkeys/:id']) {
        assert.ok(routes.includes(route), route);
    }
});

test('WebAuthn rpID/origin come from env; rpID falls back to the origin hostname', () => {
    const saved = { id: process.env.WEBAUTHN_RP_ID, origin: process.env.WEBAUTHN_ORIGIN };
    // Empty strings (not deletions): a developer dotenv file must not leak into this test.
    process.env.WEBAUTHN_RP_ID = ''; process.env.WEBAUTHN_ORIGIN = 'https://app.example.invalid';
    const file = require.resolve('../utils/config.js');
    const cached = require.cache[file];
    delete require.cache[file];
    try {
        const fresh = require('../utils/config.js');
        assert.equal(fresh.webauthn_origin, 'https://app.example.invalid');
        assert.equal(fresh.webauthn_rp_id, 'app.example.invalid');
    } finally {
        require.cache[file] = cached;
        process.env.WEBAUTHN_RP_ID = saved.id; process.env.WEBAUTHN_ORIGIN = saved.origin;
    }
});

for (const [name, entry, id] of [
    ['nested id', { deviceName: 'Old phone', passkey: { id: 'legacy-nested', publicKey: 'private-detail' } }, 'legacy-nested'],
    ['top-level id', { id: 'legacy-top', passkey: { id: 'older-id' } }, 'legacy-top'],
    ['credentialId', { credentialId: 'legacy-credential' }, 'legacy-credential'],
]) {
    test(`legacy ${name} round-trips from list to password-confirmed deletion`, async () => {
        const uuid = 'legacy-delete-' + id;
        const other = { passkey: { id: 'keep-me' } };
        h.seedUser(uuid, { legacyPasskeys: [entry, other] });
        const listed = await passkeys.list(h.strong(uuid));
        assert.equal(listed.status, 200);
        assert.equal(listed.data.passkeys[0].id, id);
        assert.equal(listed.data.passkeys[0].verified, false);
        assert.doesNotMatch(JSON.stringify(listed.data), /publicKey|private-detail/);
        assert.equal((await passkeys.remove(h.strong(uuid), { id }, {}, h.client)).status, 400);
        assert.equal((await passkeys.remove(h.strong(uuid), { id }, { password: 'wrong' }, h.client)).status, 401);
        const removed = await passkeys.remove(h.strong(uuid), { id }, { password: 'correct horse battery' }, h.client);
        assert.equal(removed.status, 200, JSON.stringify(removed.data));
        assert.deepEqual(h.userDoc(uuid).passkeys, [other]);
        assert.ok(h.auditActions(uuid).includes('passkey_deleted'));
        assert.equal((await passkeys.remove(h.strong(uuid), { id: 'unknown' }, { password: 'correct horse battery' }, h.client)).status, 404);
    });
}

test('verified deletion uses credential store and leaves matching users.passkeys entry intact', async () => {
    const uuid = 'legacy-verified-collision';
    h.seedUser(uuid);
    const { device } = await enroll(uuid);
    const legacy = { passkey: { id: device.id } };
    h.userDoc(uuid).passkeys = [legacy];
    const removed = await passkeys.remove(h.strong(uuid), { id: device.id }, { password: 'correct horse battery' }, h.client);
    assert.equal(removed.status, 200);
    assert.equal(h.credentials().some(c => c.credentialId === device.id), false);
    assert.deepEqual(h.userDoc(uuid).passkeys, [legacy]);
});
