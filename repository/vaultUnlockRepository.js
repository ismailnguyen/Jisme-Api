'use strict';
// Per-user vault unlock state. Being signed in (authenticated) is NOT being
// unlocked: this record only exists after a successful unlock ceremony.
// Document: { _id: H(uuid), unlockId, method, credentialId, createdAt, expiresAt }
const repository = require('./ports/repositoryPort.js');
const { assertSupported, keyOf } = require('./atomicSupport.js');

const collection = 'vault_unlock_state';
const idOf = (uuid) => keyOf('jisme.vault.unlock.v1', uuid);

// Replaces any previous unlock state (the newest unlock wins).
exports.set = async function (uuid, { unlockId, method, credentialId, createdAt, expiresAt }) {
    assertSupported();
    await repository.findOneAndDelete(collection, { filter: { _id: idOf(uuid) } });
    return repository.insertOneExclusive(collection, { document: { _id: idOf(uuid), unlockId, method, credentialId, createdAt, expiresAt } });
};

exports.find = async function (uuid) {
    assertSupported();
    return repository.findOne(collection, { filter: { _id: idOf(uuid) } });
};

exports.clear = async function (uuid) {
    assertSupported();
    return repository.findOneAndDelete(collection, { filter: { _id: idOf(uuid) } });
};
