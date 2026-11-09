'use strict';
// Opaque client vault envelopes. See docs/vault-envelope-design.md.
const { createHash } = require('node:crypto');
const { db_repository_type } = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const collection = 'vault_envelopes';

// The Data API adapter cannot provide exclusive insert / compare-and-set.
function assertSupported() {
    if (db_repository_type === 'api') {
        throw new Error('Vault envelopes require the Mongo repository');
    }
}

// Deterministic _id gives per-(owner, vault) uniqueness without an extra index.
function documentId(owner, vaultId) {
    return createHash('sha256').update(owner + '\0' + vaultId).digest('hex');
}

exports.list = async function (owner) {
    assertSupported();
    return repository.findAll(collection, { filter: { owner }, projection: { 'envelope.ct': 0 } });
};

exports.findOne = async function (owner, vaultId) {
    assertSupported();
    return repository.findOne(collection, { filter: { _id: documentId(owner, vaultId), owner, vaultId } });
};

exports.count = async function (owner) {
    assertSupported();
    return repository.count(collection, { filter: { owner } });
};

// Returns false when the (owner, vaultId) document already exists.
exports.insert = async function ({ owner, vaultId, revision, envelope, size, updatedAt }) {
    assertSupported();
    return repository.insertOneExclusive(collection, {
        document: { _id: documentId(owner, vaultId), owner, vaultId, revision, envelope, size, updatedAt }
    });
};

// Single atomic update conditioned on the expected revision; null on mismatch.
exports.compareAndSet = async function (owner, vaultId, expectedRevision, { revision, envelope, size, updatedAt }) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { _id: documentId(owner, vaultId), owner, vaultId, revision: expectedRevision },
        update: { revision, envelope, size, updatedAt }
    });
};

// Single atomic delete conditioned on the expected revision; null on mismatch.
exports.compareAndDelete = async function (owner, vaultId, expectedRevision) {
    assertSupported();
    return repository.findOneAndDelete(collection, {
        filter: { _id: documentId(owner, vaultId), owner, vaultId, revision: expectedRevision }
    });
};
