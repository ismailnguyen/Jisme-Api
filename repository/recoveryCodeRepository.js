'use strict';
// One recovery code per user, stored ONLY as a salted scrypt hash.
// Document: { _id: H(uuid), algo, salt, hash, createdAt, rotatedAt }
const repository = require('./ports/repositoryPort.js');
const { assertSupported, keyOf } = require('./atomicSupport.js');

const collection = 'recovery_codes';
const idOf = (uuid) => keyOf('jisme.recovery.owner.v1', uuid);

// Exclusive: returns false if the user already has a recovery code.
exports.insertIfAbsent = async function (uuid, { algo, salt, hash, createdAt }) {
    assertSupported();
    return repository.insertOneExclusive(collection, { document: { _id: idOf(uuid), algo, salt, hash, createdAt, rotatedAt: null } });
};

exports.find = async function (uuid) {
    assertSupported();
    return repository.findOne(collection, { filter: { _id: idOf(uuid) } });
};

// One-time use: replace the hash only if it is still the one that was verified.
// A concurrent second use of the same code loses this compare-and-set.
exports.rotate = async function (uuid, expectedHash, { algo, salt, hash, rotatedAt }) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { _id: idOf(uuid), hash: expectedHash },
        update: { algo, salt, hash, rotatedAt },
    });
};
