'use strict';
// Password login: the last_login_date cooldown (which only ever locked out
// legitimate users, since it is written on success only) is gone. Abuse is
// bounded by the same fail-closed per-user 'login' rate limit as passkey login.
const { test, mock } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');

const users = require('../controllers/userController.js');
const userService = require('../services/userService.js');
const limiter = require('../services/vaultRateLimit.js');
const netlify = require('../netlify/functions/users/index.js');

const PASSWORD = 'correct horse battery';
const recently = () => new Date(Date.now() - 10 * 1000).toISOString();

test('password login succeeds even when the last successful login was < 300s ago', async () => {
    h.seedUser('pwd-cd-1').last_login_date = recently();
    const r = await users.verifyPassword(h.preAuth('pwd-cd-1'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.ok(r.data.token);
    assert.deepEqual(h.decodeJwt(r.data.token).amr, ['pwd']);

    // Immediate re-login (e.g. after a buggy logout) is allowed too.
    const again = await users.verifyPassword(h.preAuth('pwd-cd-1'), { password: PASSWORD }, h.client);
    assert.equal(again.status, 200, JSON.stringify(again.data));
});

test('successful password login still records last_login_date', async () => {
    const previous = recently();
    h.seedUser('pwd-cd-2').last_login_date = previous;
    const before = Date.now();
    const r = await users.verifyPassword(h.preAuth('pwd-cd-2'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const stored = h.userDoc('pwd-cd-2').last_login_date;
    assert.notEqual(stored, previous);
    assert.ok(Date.parse(stored) >= before - 1000);
    assert.equal(r.data.last_login_date, stored);
});

test('21st password attempt within a minute gets 429 with retryAfterSeconds', async () => {
    h.seedUser('pwd-rl');
    const budget = limiter.LIMITS.LOGIN_PER_WINDOW;
    assert.equal(budget, 20);
    // Failed attempts count against the budget (this is the brute-force bound).
    for (let i = 0; i < budget; i++) {
        const r = await users.verifyPassword(h.preAuth('pwd-rl'), { password: 'wrong-' + i }, h.client);
        assert.notEqual(r.status, 429, `attempt ${i + 1} must not be rate limited`);
    }
    // Even the correct password is refused once the budget is spent.
    const r = await users.verifyPassword(h.preAuth('pwd-rl'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 429, JSON.stringify(r.data));
    assert.equal(r.data.token, undefined);
    const seconds = Number(r.headers && r.headers['Retry-After']);
    assert.ok(Number.isInteger(seconds) && seconds >= 1 && seconds <= 60, String(seconds));

    const nf = await netlify.handler({
        httpMethod: 'POST', path: '/.netlify/functions/users/login/password',
        headers: h.preAuth('pwd-rl'), body: JSON.stringify({ password: PASSWORD }),
    });
    assert.equal(nf.statusCode, 429, nf.body);
    assert.match(nf.headers['Retry-After'], /^\d+$/);

    await assert.rejects(
        userService.verifyPassword('pwd-rl', PASSWORD, false, h.client),
        (error) => error.code === 429
            && Number.isInteger(error.retryAfterSeconds)
            && error.retryAfterSeconds >= 1 && error.retryAfterSeconds <= 60,
    );
});

test('password login budget is per user', async () => {
    h.seedUser('pwd-rl-other');
    const r = await users.verifyPassword(h.preAuth('pwd-rl-other'), { password: PASSWORD }, h.client);
    assert.equal(r.status, 200, JSON.stringify(r.data));
});

test('rate limiter fault fails closed: clean 429, no session, no crash', async () => {
    h.seedUser('pwd-rl-fault');
    const consume = mock.method(limiter, 'consume', () => { throw new Error('limiter down'); });
    try {
        const r = await users.verifyPassword(h.preAuth('pwd-rl-fault'), { password: PASSWORD }, h.client);
        assert.equal(r.status, 429, JSON.stringify(r.data));
        assert.equal(r.data.token, undefined);
        assert.equal(r.headers['Retry-After'], '60');
        assert.doesNotMatch(JSON.stringify(r.data), /limiter down/);
        assert.equal(consume.mock.callCount(), 1);
        assert.equal(h.userDoc('pwd-rl-fault').last_login_date, undefined);
    } finally {
        consume.mock.restore();
    }
});
