'use strict';
// Verified WebAuthn credentials (only written after verifyRegistrationResponse).
// Document: { _id: H(credentialId), credentialId, owner: H(uuid), publicKey, name?,
//   counter, transports, validated: true, createdAt, lastUsedAt }
// Legacy, never-verified passkeys live in users.passkeys and are NEVER read here.
const repository = require('./ports/repositoryPort.js');
const { assertSupported, keyOf } = require('./atomicSupport.js');

const collection = 'webauthn_credentials';
const ownerOf = (uuid) => keyOf('jisme.webauthn.owner.v1', uuid);
const idOf = (credentialId) => keyOf('jisme.webauthn.credential.v1', credentialId);

exports.ownerOf = ownerOf;

// Globally unique credential id: a second registration of the same id fails.
// rpId/userHandle/legacy are only set for passkeys promoted from users.passkeys.
exports.insert = async function (uuid, { credentialId, publicKey, counter, transports, createdAt, name, rpId, userHandle, legacy }) {
    assertSupported();
    return repository.insertOneExclusive(collection, { document: {
        _id: idOf(credentialId), credentialId, owner: ownerOf(uuid), publicKey, counter,
        transports, validated: true, createdAt, lastUsedAt: null,
        ...(typeof name === 'string' && name ? { name } : {}),
        ...(legacy ? { rpId, userHandle, legacy: true } : {}),
    } });
};

exports.listByUser = async function (uuid) {
    assertSupported();
    return repository.findAll(collection, { filter: { owner: ownerOf(uuid), validated: true } });
};

exports.findForUser = async function (uuid, credentialId) {
    assertSupported();
    if (typeof credentialId !== 'string' || !credentialId) return null;
    return repository.findOne(collection, { filter: { _id: idOf(credentialId), owner: ownerOf(uuid), validated: true } });
};

// Atomic sign-count advance: succeeds only if nobody else used the counter value.
exports.compareAndSetCounter = async function (uuid, credentialId, expected, { counter, lastUsedAt }) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { _id: idOf(credentialId), owner: ownerOf(uuid), counter: expected },
        update: { counter, lastUsedAt },
    });
};

exports.remove = async function (uuid, credentialId) {
    assertSupported();
    if (typeof credentialId !== 'string' || !credentialId) return null;
    return repository.findOneAndDelete(collection, { filter: { _id: idOf(credentialId), owner: ownerOf(uuid) } });
};

exports.removeAll = async function (uuid) {
    assertSupported();
    let removed = 0;
    // Bounded by MAX_PASSKEYS_PER_USER; single-document deletes keep the adapter surface small.
    for (let i = 0; i < 64; i++) {
        const deleted = await repository.findOneAndDelete(collection, { filter: { owner: ownerOf(uuid) } });
        if (!deleted) break;
        removed += 1;
    }
    return removed;
};
