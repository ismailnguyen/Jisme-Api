'use strict';

// Red test: trusted session resolution with a deliberate auth_time claim.
// Covers report step 2 of the integration contract: tokens issued on
// completed authentication must carry auth_time; verifyAccessToken must
// return it; a production session resolver must feed ceremonies and fail
// closed on pre-auth tokens. Freshness window itself is enforced by
// webauthnCeremonies and covered in ceremonies.test.cjs.

const test = require('node:test');
const assert = require('node:assert');

process.env.TOKEN_MASTER_SECRET = 'unit-test-token-secret';

const {
  generateSignedAccessToken,
  generateUnsignedAccessToken,
  verifyAccessToken,
  generateFreshSessionResolver
} = require('../utils/credentials.js');

const client = { agent: 'test-agent', referer: 'https://jisme.example', ip: '127.0.0.1' };

test('signed access token carries a deliberate auth_time claim', async () => {
  const before = Math.floor(Date.now() / 1000);
  const token = generateSignedAccessToken({ email: 'a@example.com', uuid: 'u1' }, false, client);
  const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

  assert.ok(Number.isSafeInteger(decoded.auth_time), 'auth_time must be an integer');
  assert.ok(decoded.auth_time >= before, 'auth_time must not be in the past');
  assert.ok(decoded.auth_time <= Math.floor(Date.now() / 1000) + 1, 'auth_time must be current');
  assert.strictEqual(decoded.isAuthorized, true);
});

test('pre-auth token deliberately has no auth_time claim', async () => {
  const token = generateUnsignedAccessToken({ email: 'a@example.com', uuid: 'u1' }, client);
  const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

  assert.strictEqual(decoded.auth_time, undefined);
  assert.strictEqual(decoded.isAuthorized, false);
});

test('verifyAccessToken returns auth_time for a fresh signed token', async () => {
  const token = generateSignedAccessToken({ email: 'a@example.com', uuid: 'u1' }, true, client);
  const session = await verifyAccessToken('Bearer ' + token);

  assert.strictEqual(session.uuid, 'u1');
  assert.strictEqual(session.isAuthorized, true);
  assert.ok(Number.isSafeInteger(session.auth_time), 'verifyAccessToken must expose auth_time');
});

test('production session resolver exposes the authenticated session for ceremonies', async () => {
  const token = generateSignedAccessToken({ email: 'a@example.com', uuid: 'u1' }, false, client);
  const resolver = generateFreshSessionResolver();
  const session = await resolver('Bearer ' + token);

  assert.strictEqual(session.uuid, 'u1');
  assert.strictEqual(session.isAuthorized, true);
  assert.ok(Number.isSafeInteger(session.auth_time));
});

test('production session resolver fails closed on pre-auth token', async () => {
  const token = generateUnsignedAccessToken({ email: 'a@example.com', uuid: 'u1' }, client);
  const resolver = generateFreshSessionResolver();

  // utils/errors.js Exception is a plain object with a .code field, not an Error instance.
  await assert.rejects(() => resolver('Bearer ' + token), (error) => {
    assert.strictEqual(error.code, 401);
    return true;
  });
});

test('production session resolver fails closed on missing bearer token', async () => {
  const resolver = generateFreshSessionResolver();
  await assert.rejects(() => resolver(undefined));
});
