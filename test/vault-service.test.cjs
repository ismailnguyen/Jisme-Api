'use strict';
// Vault envelope service + repository semantics on the mock adapter.
// See docs/vault-envelope-design.md.
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Synthetic store prevents checked-in mock fixtures/config/secrets being loaded.
global.__JISME_MOCK_STORE__ = { users: [], accounts: [], activities: [], webauthnChallenges: [], vaultEnvelopes: [] };
process.env.NODE_ENV = 'production';
process.env.DB_REPOSITORY_TYPE = 'mock';

const vault = require('../services/vaultService.js');

const ct = (bytes, fill = 7) => Buffer.alloc(bytes, fill).toString('base64url');
const envelope = (bytes = 64, fill = 7) => ({ v: 1, ct: ct(bytes, fill) });
const rejectsWith = (code, pattern) => (error) => {
    assert.equal(error.code, code, `expected ${code}, got ${error.code} (${error.message}: ${error.reason})`);
    if (pattern) assert.match(`${error.message} ${error.reason}`, pattern);
    return true;
};
const stored = () => global.__JISME_MOCK_STORE__.vaultEnvelopes;

test('create, read, replace with compare-and-set revisions', async () => {
    const created = await vault.put('alice', 'primary', { expectedRevision: 0, envelope: envelope(64, 1) });
    assert.equal(created.created, true);
    assert.equal(created.vaultId, 'primary');
    assert.equal(created.revision, 1);
    assert.ok(!Number.isNaN(Date.parse(created.updatedAt)));

    const read = await vault.get('alice', 'primary');
    assert.deepEqual(read.envelope, envelope(64, 1));
    assert.equal(read.revision, 1);

    const replaced = await vault.put('alice', 'primary', { expectedRevision: 1, envelope: envelope(64, 2) });
    assert.equal(replaced.created, false);
    assert.equal(replaced.revision, 2);
    assert.deepEqual((await vault.get('alice', 'primary')).envelope, envelope(64, 2));
});

test('stale writer cannot clobber a newer envelope', async () => {
    await vault.put('bob', 'primary', { expectedRevision: 0, envelope: envelope(64, 1) });
    await vault.put('bob', 'primary', { expectedRevision: 1, envelope: envelope(64, 2) });

    await assert.rejects(vault.put('bob', 'primary', { expectedRevision: 1, envelope: envelope(64, 9) }),
        (error) => rejectsWith(409)(error) && error.currentRevision === 2);
    await assert.rejects(vault.put('bob', 'primary', { expectedRevision: 0, envelope: envelope(64, 9) }),
        (error) => rejectsWith(409)(error) && error.currentRevision === 2);
    await assert.rejects(vault.put('bob', 'absent', { expectedRevision: 1, envelope: envelope(64, 9) }),
        (error) => rejectsWith(409)(error) && error.currentRevision === 0);
    assert.deepEqual((await vault.get('bob', 'primary')).envelope, envelope(64, 2));
});

test('concurrent writers: exactly one create and one replace win', async () => {
    const creates = await Promise.allSettled(Array.from({ length: 10 }, (_, i) =>
        vault.put('carol', 'primary', { expectedRevision: 0, envelope: envelope(64, i) })));
    assert.equal(creates.filter((r) => r.status === 'fulfilled').length, 1);
    assert.ok(creates.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 409));

    const replaces = await Promise.allSettled(Array.from({ length: 10 }, (_, i) =>
        vault.put('carol', 'primary', { expectedRevision: 1, envelope: envelope(64, 100 + i) })));
    assert.equal(replaces.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal((await vault.get('carol', 'primary')).revision, 2);
});

test('per-user isolation: another user cannot see, overwrite or delete', async () => {
    await vault.put('dave', 'primary', { expectedRevision: 0, envelope: envelope(64, 4) });

    assert.deepEqual(await vault.list('mallory'), []);
    await assert.rejects(vault.get('mallory', 'primary'), rejectsWith(404));
    await assert.rejects(vault.put('mallory', 'primary', { expectedRevision: 1, envelope: envelope(64, 6) }),
        (error) => rejectsWith(409)(error) && error.currentRevision === 0);
    await assert.rejects(vault.remove('mallory', 'primary', 1), rejectsWith(409));

    // Mallory can create her own vault with the same name without touching Dave's.
    await vault.put('mallory', 'primary', { expectedRevision: 0, envelope: envelope(64, 6) });
    assert.deepEqual((await vault.get('dave', 'primary')).envelope, envelope(64, 4));
    assert.equal((await vault.get('dave', 'primary')).revision, 1);
});

test('stored document holds no raw uuid, only opaque envelope + metadata', async () => {
    await vault.put('erin-uuid-secret', 'primary', { expectedRevision: 0, envelope: envelope(64, 5) });
    const doc = stored().find((d) => d.envelope.ct === ct(64, 5));
    assert.ok(doc);
    assert.doesNotMatch(JSON.stringify(doc), /erin-uuid-secret/);
    assert.match(doc.owner, /^[0-9a-f]{64}$/);
    assert.deepEqual(Object.keys(doc).sort(), ['_id', 'envelope', 'owner', 'revision', 'size', 'updatedAt', 'vaultId']);
    assert.deepEqual(Object.keys(doc.envelope).sort(), ['ct', 'v']);
});

test('list returns metadata only, never ciphertext', async () => {
    await vault.put('frank', 'primary', { expectedRevision: 0, envelope: envelope(64, 8) });
    await vault.put('frank', 'work', { expectedRevision: 0, envelope: envelope(100, 8) });
    const list = await vault.list('frank');
    assert.deepEqual(list.map((v) => v.vaultId).sort(), ['primary', 'work']);
    for (const item of list) {
        assert.deepEqual(Object.keys(item).sort(), ['revision', 'size', 'updatedAt', 'v', 'vaultId']);
    }
    assert.equal(list.find((v) => v.vaultId === 'work').size, 100);
    assert.doesNotMatch(JSON.stringify(list), new RegExp(ct(64, 8)));
});

test('delete requires matching revision', async () => {
    await vault.put('grace', 'primary', { expectedRevision: 0, envelope: envelope() });
    await vault.put('grace', 'primary', { expectedRevision: 1, envelope: envelope() });
    await assert.rejects(vault.remove('grace', 'primary', 1), (error) => rejectsWith(409)(error) && error.currentRevision === 2);
    assert.deepEqual(await vault.remove('grace', 'primary', 2), { vaultId: 'primary', deleted: true });
    await assert.rejects(vault.get('grace', 'primary'), rejectsWith(404));
    await assert.rejects(vault.remove('grace', 'primary', 2), (error) => rejectsWith(409)(error) && error.currentRevision === 0);
});

for (const [name, bad] of [
    ['v:2', { v: 2, ct: ct(64) }],
    ['v:"1"', { v: '1', ct: ct(64) }],
    ['v:0', { v: 0, ct: ct(64) }],
    ['missing v', { ct: ct(64) }],
]) {
    test(`unknown envelope version rejected: ${name}`, async () => {
        await assert.rejects(vault.put('henry', 'primary', { expectedRevision: 0, envelope: bad }), rejectsWith(400, /version/i));
    });
}

for (const [name, bad] of [
    ['extra salt field', { v: 1, ct: ct(64), salt: ct(16) }],
    ['plaintext field', { v: 1, ct: ct(64), plaintext: 'hunter2' }],
    ['key field', { v: 1, ct: ct(64), key: ct(32) }],
    ['padded base64', { v: 1, ct: ct(64) + '==' }],
    ['standard base64 alphabet', { v: 1, ct: '+/' + ct(64) }],
    ['non-canonical trailing bits', { v: 1, ct: 'AB' + ct(63) }],
    ['non-string ct', { v: 1, ct: 12345 }],
    ['ct object', { v: 1, ct: { data: ct(64) } }],
    ['too short (27 bytes)', { v: 1, ct: ct(27) }],
    ['array envelope', [1, ct(64)]],
    ['null envelope', null],
]) {
    test(`malformed envelope rejected: ${name}`, async () => {
        await assert.rejects(vault.put('ivan', 'primary', { expectedRevision: 0, envelope: bad }), rejectsWith(400));
        assert.deepEqual(await vault.list('ivan'), []);
    });
}

test('size bounds: max accepted, max+1 is 413', async () => {
    const max = vault.LIMITS.MAX_CIPHERTEXT_BYTES;
    assert.equal(max, 524288);
    await vault.put('judy', 'big', { expectedRevision: 0, envelope: { v: 1, ct: ct(max) } });
    await assert.rejects(vault.put('judy', 'bigger', { expectedRevision: 0, envelope: { v: 1, ct: ct(max + 1) } }), rejectsWith(413));
    await vault.put('judy', 'min', { expectedRevision: 0, envelope: { v: 1, ct: ct(28) } });
});

for (const [name, body] of [
    ['missing expectedRevision', { envelope: envelope() }],
    ['negative revision', { expectedRevision: -1, envelope: envelope() }],
    ['fractional revision', { expectedRevision: 1.5, envelope: envelope() }],
    ['string revision', { expectedRevision: '0', envelope: envelope() }],
    ['unsafe integer revision', { expectedRevision: 2 ** 53, envelope: envelope() }],
    ['unknown top-level key', { expectedRevision: 0, envelope: envelope(), kdf: { iterations: 1 } }],
    ['client-chosen owner', { expectedRevision: 0, envelope: envelope(), uuid: 'victim' }],
    ['__proto__ key', JSON.parse(`{"expectedRevision":0,"envelope":${JSON.stringify(envelope())},"__proto__":{"x":1}}`)],
    ['null body', null],
    ['array body', [0, envelope()]],
]) {
    test(`malformed write body rejected: ${name}`, async () => {
        await assert.rejects(vault.put('kate', 'primary', body), rejectsWith(400));
        assert.deepEqual(await vault.list('kate'), []);
    });
}

for (const id of ['', 'A', 'Primary', '-lead', '../x', 'a/b', 'a'.repeat(33), '__proto__', 'a b', 42, null, undefined]) {
    test(`invalid vaultId rejected: ${JSON.stringify(id)}`, async () => {
        await assert.rejects(vault.put('liam', id, { expectedRevision: 0, envelope: envelope() }), rejectsWith(400));
        await assert.rejects(vault.get('liam', id), rejectsWith(400));
        await assert.rejects(vault.remove('liam', id, 1), rejectsWith(400));
    });
}

for (const rev of [0, -1, 1.5, '1', null, undefined]) {
    test(`delete requires a positive integer revision: ${JSON.stringify(rev)}`, async () => {
        await assert.rejects(vault.remove('liam', 'primary', rev), rejectsWith(400));
    });
}

test('missing uuid fails closed', async () => {
    for (const uuid of ['', null, undefined, 42]) {
        await assert.rejects(vault.list(uuid), rejectsWith(401));
        await assert.rejects(vault.put(uuid, 'primary', { expectedRevision: 0, envelope: envelope() }), rejectsWith(401));
    }
});

test('per-user vault count is bounded', async () => {
    const max = vault.LIMITS.MAX_VAULTS_PER_USER;
    assert.equal(max, 8);
    for (let i = 0; i < max; i++) {
        await vault.put('mia', `v${i}`, { expectedRevision: 0, envelope: envelope() });
    }
    await assert.rejects(vault.put('mia', 'one-too-many', { expectedRevision: 0, envelope: envelope() }), rejectsWith(403));
    // Replacing an existing vault is still allowed at the limit.
    await vault.put('mia', 'v0', { expectedRevision: 1, envelope: envelope() });
});
