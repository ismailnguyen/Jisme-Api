'use strict';
// Settings → Security: list() must flag passkeys from the verified credential
// store as `verified: true` (legacy users.passkeys stay `verified: false`), and
// an optional, sanitized `name` supplied at enrollment is stored and listed.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers-auth.cjs');
const { authenticator } = require('./fixtures.cjs');

const passkeys = require('../controllers/passkeyController.js');

async function enroll(uuid, extra = {}) {
    const headers = h.strong(uuid);
    const options = await passkeys.enrollmentOptions(headers, {}, h.client);
    assert.equal(options.status, 200, JSON.stringify(options.data));
    const device = authenticator();
    const response = device.register(options.data.challenge);
    const result = await passkeys.enroll(headers, { challenge: options.data.challenge, response, ...extra }, h.client);
    return { device, result };
}

const listOf = async (uuid) => {
    const r = await passkeys.list(h.strong(uuid));
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return r.data.passkeys;
};

test('list: a verified credential is flagged verified: true', async () => {
    h.seedUser('plv-1');
    const { device, result } = await enroll('plv-1');
    assert.equal(result.status, 201);
    const items = await listOf('plv-1');
    assert.equal(items.length, 1);
    assert.equal(items[0].id, device.id);
    assert.equal(items[0].verified, true);
});

test('list: a legacy users.passkeys entry stays verified: false', async () => {
    h.seedUser('plv-2', { legacyPasskeys: [{ deviceName: 'Old phone', passkey: { id: 'legacy-plv-2' } }] });
    const items = await listOf('plv-2');
    assert.deepEqual(items, [{ id: 'legacy-plv-2', deviceName: 'Old phone', verified: false }]);
});

test('list: verified + legacy + legacy duplicate of the verified id → duplicate dropped, verified wins', async () => {
    h.seedUser('plv-3');
    const { device } = await enroll('plv-3');
    h.userDoc('plv-3').passkeys = [{ passkey: { id: device.id } }, { passkey: { id: 'legacy-plv-3' } }];
    const items = await listOf('plv-3');
    assert.equal(items.length, 2);
    const same = items.filter((p) => p.id === device.id);
    assert.equal(same.length, 1);
    assert.equal(same[0].verified, true);
    assert.equal(items.find((p) => p.id === 'legacy-plv-3').verified, false);
});

test('enroll with a name: stored (trimmed, ≤ 64 chars), returned, and listed', async () => {
    h.seedUser('plv-4');
    const { device, result } = await enroll('plv-4', { name: '  My MacBook  ' });
    assert.equal(result.status, 201, JSON.stringify(result.data));
    assert.equal(result.data.name, 'My MacBook');
    assert.equal(h.credentials().find((c) => c.credentialId === device.id).name, 'My MacBook');
    const items = await listOf('plv-4');
    assert.equal(items[0].name, 'My MacBook');
    assert.equal(items[0].verified, true);

    h.seedUser('plv-4b');
    const long = await enroll('plv-4b', { name: 'x'.repeat(100) });
    assert.equal(long.result.status, 201);
    assert.equal(long.result.data.name, 'x'.repeat(64));
    assert.equal(h.credentials().find((c) => c.credentialId === long.device.id).name.length, 64);
});

test('enroll without a name (or with an invalid one): OK, no name stored or returned', async () => {
    for (const [uuid, extra] of [['plv-5', {}], ['plv-5b', { name: 42 }], ['plv-5c', { name: '   ' }], ['plv-5d', { name: { $ne: 1 } }]]) {
        h.seedUser(uuid);
        const { device, result } = await enroll(uuid, extra);
        assert.equal(result.status, 201, JSON.stringify(result.data));
        assert.equal('name' in result.data, false, uuid);
        assert.equal('name' in h.credentials().find((c) => c.credentialId === device.id), false, uuid);
        const items = await listOf(uuid);
        assert.equal('name' in items[0], false, uuid);
        assert.equal(items[0].verified, true);
    }
});
