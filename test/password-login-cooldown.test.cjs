'use strict';
// Password login keeps the original last_login_date cooldown
// (LOGIN_DELAY_IN_SECONDS, default 300s) and is NOT subject to the in-memory
// per-user 'login' rate limit, which only bounds passkey ceremonies.
const { test, mock } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');

const users = require('../controllers/userController.js');
const limiter = require('../services/vaultRateLimit.js');

const PASSWORD = 'correct horse battery';
const recently = () => new Date(Date.now() - 10 * 1000).toISOString();
const longAgo = () => new Date(Date.now() - 3600 * 1000).toISOString();

test('password login within the cooldown after the last login is refused (401), as before', async () => {
    h.seedUser('pwd-cd-1').last_login_date = recently();
    const r = await users.verifyPassword(h.preAuth('pwd-cd-1'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 401, JSON.stringify(r.data));
    assert.match(r.data.error.reason, /Too many login attempt/);
    assert.equal(r.data.token, undefined);
});

test('password login after the cooldown succeeds and records last_login_date', async () => {
    const previous = longAgo();
    h.seedUser('pwd-cd-2').last_login_date = previous;
    const before = Date.now();
    const r = await users.verifyPassword(h.preAuth('pwd-cd-2'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(h.decodeJwt(r.data.token).amr, ['pwd']);
    const stored = h.userDoc('pwd-cd-2').last_login_date;
    assert.notEqual(stored, previous);
    assert.ok(Date.parse(stored) >= before - 1000);
});

test('password attempts are not counted against the in-memory login rate limit', async () => {
    h.seedUser('pwd-rl');
    const consume = mock.method(limiter, 'consume');
    try {
        for (let i = 0; i < limiter.LIMITS.LOGIN_PER_WINDOW + 1; i++) {
            const r = await users.verifyPassword(h.preAuth('pwd-rl'), { password: 'wrong-' + i }, h.client);
            assert.equal(r.status, 404, `attempt ${i + 1}: ${JSON.stringify(r.data)}`);
        }
        assert.equal(consume.mock.callCount(), 0);
    } finally {
        consume.mock.restore();
    }
});
