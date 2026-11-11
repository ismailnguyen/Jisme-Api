'use strict';
// P1 recovery codes: issued once at first-run vault setup, returned ONCE, only a
// salted scrypt hash is stored; POST users/recovery/verify (fresh password+MFA
// session) consumes the code to re-enroll passkeys / reset the unlock secret,
// rotates it, is rate limited and audited. Recovery never restores vault contents.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator } = require('./fixtures.cjs');

const recovery = require('../controllers/recoveryController.js');
const passkeys = require('../controllers/passkeyController.js');
const vaults = require('../controllers/vaultController.js');
const unlockService = require('../services/vaultUnlockService.js');
const limiter = require('../services/vaultRateLimit.js');
const netlify = require('../netlify/functions/users/index.js');

const CODE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/;
const ct = (fill) => Buffer.alloc(64, fill).toString('base64url');
const create = (uuid, vaultId = 'primary', fill = 1) => vaults.put(h.strong(uuid), { vaultId }, { expectedRevision: 0, envelope: { v: 1, ct: ct(fill) } });
const codes = () => h.store().recoveryCodes || [];

async function enrolled(uuid) {
    const device = authenticator();
    const options = (await passkeys.enrollmentOptions(h.strong(uuid), {}, h.client)).data;
    const r = await passkeys.enroll(h.strong(uuid), { challenge: options.challenge, response: device.register(options.challenge) }, h.client);
    assert.equal(r.status, 201, JSON.stringify(r.data));
    return device;
}

async function setup(uuid, opts) {
    h.seedUser(uuid, opts);
    const r = await create(uuid);
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.match(r.data.recoveryCode, CODE);
    return r.data.recoveryCode;
}

test('first-run vault setup returns a recovery code exactly once; only a salted hash is stored', async () => {
    h.seedUser('rec-1');
    const first = await create('rec-1');
    assert.equal(first.status, 201);
    assert.match(first.data.recoveryCode, CODE);
    const code = first.data.recoveryCode;
    const second = await create('rec-1', 'second', 2);
    assert.equal(second.status, 201);
    assert.equal(second.data.recoveryCode, undefined, 'never returned again');

    const raw = JSON.stringify(h.store());
    assert.doesNotMatch(raw, new RegExp(code));
    assert.doesNotMatch(raw, new RegExp(code.replace(/-/g, '')));
    const docs = codes().filter((d) => d.hash);
    const doc = docs[docs.length - 1];
    assert.equal(doc.algo, 'scrypt');
    assert.match(doc.salt, /^[A-Za-z0-9_-]{22,}$/);
    assert.match(doc.hash, /^[A-Za-z0-9_-]{43}$/);
    assert.doesNotMatch(JSON.stringify(doc), /rec-1/, 'raw uuid not stored');
    assert.ok(h.auditActions('rec-1').includes('recovery_code_issued'));
});

test('POST users/recovery issues for users without a code (any authenticated session, passkey included), then 409', async () => {
    h.seedUser('rec-2');
    assert.equal((await recovery.issue(h.preAuth('rec-2'), {}, h.client)).status, 401);
    const r = await recovery.issue(h.strong('rec-2', { amr: ['webauthn'], authTime: h.nowS() - 3600 }), {}, h.client);
    assert.equal(r.status, 201);
    assert.match(r.data.recoveryCode, CODE);
    assert.equal((await recovery.issue(h.strong('rec-2'), {}, h.client)).status, 409);
    // vault first-run after explicit issuance does not issue a second code
    const v = await create('rec-2');
    assert.equal(v.data.recoveryCode, undefined);
});

const badSessions = {
    'no session': () => ({}),
    'pre-auth token': (u) => h.preAuth(u),
    'stale password session': (u) => h.strong(u, { authTime: h.nowS() - 301 }),
    'passkey-only session': (u) => h.strong(u, { amr: ['webauthn'] }),
    'legacy token without amr': (u) => h.bearer({ uuid: u, isAuthorized: true, auth_time: h.nowS() }),
};
for (const [name, headers] of Object.entries(badSessions)) {
    test(`recovery verify refuses ${name} (401) without consuming the code`, async () => {
        const uuid = 'rec-3-' + name.replace(/\W/g, '');
        const code = await setup(uuid);
        const r = await recovery.verify(headers(uuid), { recoveryCode: code, action: 'reenroll_passkeys' }, h.client);
        assert.equal(r.status, 401);
        assert.equal((await recovery.verify(h.strong(uuid), { recoveryCode: code, action: 'reenroll_passkeys' }, h.client)).status, 200);
    });
}

test('MFA users need password AND otp in the session for recovery', async () => {
    const code = await setup('rec-mfa', { mfa: true });
    assert.equal((await recovery.verify(h.strong('rec-mfa', { amr: ['pwd'] }), { recoveryCode: code, action: 'reset_unlock' }, h.client)).status, 401);
    assert.equal((await recovery.verify(h.strong('rec-mfa', { amr: ['pwd', 'otp'] }), { recoveryCode: code, action: 'reset_unlock' }, h.client)).status, 200);
});

test('wrong code is 401 and audited; malformed input and unknown action are 400', async () => {
    await setup('rec-4');
    const wrong = await recovery.verify(h.strong('rec-4'), { recoveryCode: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', action: 'reset_unlock' }, h.client);
    assert.equal(wrong.status, 401);
    assert.ok(h.auditActions('rec-4').includes('recovery_failed'));
    assert.equal((await recovery.verify(h.strong('rec-4'), { recoveryCode: 'x', action: 'reset_unlock' }, h.client)).status, 400);
    assert.equal((await recovery.verify(h.strong('rec-4'), { recoveryCode: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', action: 'restore_vault' }, h.client)).status, 400);
    assert.equal((await recovery.verify(h.strong('rec-4'), {}, h.client)).status, 400);
    h.seedUser('rec-4-none');
    assert.equal((await recovery.verify(h.strong('rec-4-none'), { recoveryCode: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', action: 'reset_unlock' }, h.client)).status, 401);
});

test('reenroll_passkeys: revokes every passkey + unlock state, rotates the code (one-time use), audited', async () => {
    const code = await setup('rec-5');
    const a = await enrolled('rec-5');
    await enrolled('rec-5');
    const options = (await vaults.unlockOptions(h.strong('rec-5'), {})).data;
    assert.equal((await vaults.unlockPasskey(h.strong('rec-5'), { challenge: options.challenge, response: a.assert(options.challenge) })).status, 200);
    assert.equal(await unlockService.isUnlocked('rec-5'), true);

    const r = await recovery.verify(h.strong('rec-5'), { recoveryCode: code.toLowerCase().replace(/-/g, ' '), action: 'reenroll_passkeys' }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(r.data.action, 'reenroll_passkeys');
    assert.equal(r.data.revokedPasskeys, 2);
    assert.match(r.data.recoveryCode, CODE);
    assert.notEqual(r.data.recoveryCode, code);
    assert.equal((await passkeys.list(h.strong('rec-5'))).data.passkeys.length, 0);
    assert.equal(h.userDoc('rec-5').hasVerifiedPasskey, false);
    assert.equal(await unlockService.isUnlocked('rec-5'), false);
    assert.ok(h.auditActions('rec-5').includes('recovery_used'));

    // old code is spent; new one works
    assert.equal((await recovery.verify(h.strong('rec-5'), { recoveryCode: code, action: 'reenroll_passkeys' }, h.client)).status, 401);
    assert.equal((await recovery.verify(h.strong('rec-5'), { recoveryCode: r.data.recoveryCode, action: 'reset_unlock' }, h.client)).status, 200);
});

test('INVARIANT: recovery never restores or exposes vault contents', async () => {
    const code = await setup('rec-6');
    const before = JSON.stringify(h.store().vaultEnvelopes.filter((d) => d.vaultId === 'primary'));
    const r = await recovery.verify(h.strong('rec-6'), { recoveryCode: code, action: 'reset_unlock' }, h.client);
    assert.equal(r.status, 200);
    assert.equal(r.data.action, 'reset_unlock');
    assert.doesNotMatch(JSON.stringify(r.data), /envelope|"ct"|"v":/i);
    assert.match(r.data.notice, /cannot (restore|recover)/i);
    assert.equal(JSON.stringify(h.store().vaultEnvelopes.filter((d) => d.vaultId === 'primary')), before, 'ciphertext untouched');
});

test('concurrent verifies with the same code: exactly one succeeds', async () => {
    const code = await setup('rec-7');
    const results = await Promise.all(Array.from({ length: 5 }, () => recovery.verify(h.strong('rec-7'), { recoveryCode: code, action: 'reset_unlock' }, h.client)));
    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.ok(results.every((r) => r.status === 200 || r.status === 401));
});

test('recovery verify is rate limited per user, even for the right code', async () => {
    const code = await setup('rec-rl');
    let last;
    for (let i = 0; i < limiter.LIMITS.RECOVERY_PER_WINDOW; i++) {
        last = await recovery.verify(h.strong('rec-rl'), { recoveryCode: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', action: 'reset_unlock' }, h.client);
        assert.equal(last.status, 401);
    }
    last = await recovery.verify(h.strong('rec-rl'), { recoveryCode: code, action: 'reset_unlock' }, h.client);
    assert.equal(last.status, 429);
    assert.ok(Number(last.headers['Retry-After']) >= 1);
});

test('PRF material in recovery payloads is refused', async () => {
    const code = await setup('rec-8');
    const r = await recovery.verify(h.strong('rec-8'), { recoveryCode: code, action: 'reset_unlock', prfOutput: 'secret' }, h.client);
    assert.equal(r.status, 400);
    assert.match(r.data.error.reason, /PRF/);
    assert.equal((await recovery.issue(h.strong('rec-8'), { prf: 1 }, h.client)).status, 400);
});

test('Netlify users function routes recovery endpoints', async () => {
    h.seedUser('rec-nf');
    const headers = h.strong('rec-nf');
    let r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/users/recovery', headers, body: '{}' });
    assert.equal(r.statusCode, 201, r.body);
    const { recoveryCode } = JSON.parse(r.body);
    r = await netlify.handler({ httpMethod: 'POST', path: '/.netlify/functions/users/recovery/verify', headers, body: JSON.stringify({ recoveryCode, action: 'reset_unlock' }) });
    assert.equal(r.statusCode, 200, r.body);
});

test('Express user routes mount the recovery endpoints', () => {
    const routes = [];
    const app = { route: (path) => { const r = {}; for (const m of ['get', 'post', 'put', 'delete']) r[m] = () => { routes.push(m.toUpperCase() + ' ' + path); return r; }; return r; } };
    require('../server/routes/userRoutes.js')(app);
    for (const route of ['POST /users/recovery', 'POST /users/recovery/verify']) assert.ok(routes.includes(route), route);
});
