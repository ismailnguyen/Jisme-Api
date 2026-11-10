'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const h = require('./helpers-auth.cjs');
const users = require('../controllers/userController.js');
const userService = require('../services/userService.js');
const { throwError, generateError } = require('../utils/errors.js');
const netlify = require('../netlify/functions/users/index.js');

test('register forwards client through the PRF wrapper and returns the 201 shape', async (t) => {
    const payload = { email: 'client@example.invalid', password: 'password' };
    const user = { email: payload.email, uuid: 'registered-user' };
    t.mock.method(userService, 'register', async (received, client) => {
        assert.deepEqual(received, payload);
        assert.strictEqual(client, h.client);
        return user;
    });
    assert.deepEqual(await users.register(payload, h.client), { status: 201, data: user });
});

test('native controller errors return clean 500 JSON responses', async (t) => {
    const error = new Error('Registration failed');
    const expected = { status: 500, data: { error: { message: error.message, reason: error.message } } };
    assert.deepEqual(throwError(error), expected);
    t.mock.method(userService, 'register', async () => { throw error; });
    assert.deepEqual(await users.register({ email: 'error@example.invalid', password: 'password' }, h.client), expected);
    assert.deepEqual(JSON.parse(JSON.stringify(expected)), expected);
});

test('throwError preserves exception responses and handles missing error details', () => {
    assert.deepEqual(throwError(generateError('Invalid input', 'Missing email', 400)), {
        status: 400, data: { error: { message: 'Invalid input', reason: 'Missing email' } }
    });
    for (const error of [undefined, null, {}]) {
        assert.deepEqual(throwError(error), {
            status: 500, data: { error: { message: 'Error', reason: 'Unexpected error' } }
        });
    }
    assert.deepEqual(throwError({ code: 503, message: 'Unavailable', reason: 'Try later', toJSON: true }), {
        status: 503, data: { error: { message: 'Unavailable', reason: 'Try later' } }
    });
});

test('Netlify registration with a fresh email creates the user document', async () => {
    const email = `register-${randomUUID()}@example.invalid`;
    assert.equal(h.store().users.some((user) => user.email === email), false);
    const result = await netlify.handler({
        httpMethod: 'POST',
        path: '/.netlify/functions/users/register',
        headers: { 'user-agent': h.client.agent, host: h.client.referer, 'x-nf-client-connection-ip': h.client.ip },
        body: JSON.stringify({ email, password: 'correct horse battery' }),
    });
    assert.equal(result.statusCode, 201, result.body);
    const user = JSON.parse(result.body);
    assert.equal(user.email, email);
    assert.ok(user.uuid);
    assert.equal(user.hasAccounts, false);
    assert.ok(h.store().users.some((doc) => doc.uuid === user.uuid && doc.email === email));
    assert.deepEqual(h.decodeJwt(user.token).client, h.client);
});
