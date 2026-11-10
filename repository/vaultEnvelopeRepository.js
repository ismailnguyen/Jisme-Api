'use strict';
// Opaque client vault envelopes. See docs/vault-envelope-design.md.
const { createHash } = require('node:crypto');
const { db_repository_type, node_env } = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const collection = 'vault_envelopes';
const quotas = 'vault_quotas';

// Every live envelope is v1; a deleted vault is a tombstone with `envelope: null`
// (equality filters only, so the mock adapter mirrors Mongo exactly).
const LIVE = Object.freeze({ 'envelope.v': 1 });

// Allowlist (fail closed): only the Mongo adapter provides exclusive insert and
// single-document compare-and-set. The in-memory mock is for tests/dev only.
function assertSupported() {
    const supported = db_repository_type === 'db'
        || (db_repository_type === 'mock' && node_env !== 'production');
    if (!supported) {
        throw new Error('Vault envelopes require the Mongo repository');
    }
}

// Deterministic _id gives per-(owner, vault) uniqueness without an extra index.
function documentId(owner, vaultId) {
    return createHash('sha256').update(owner + '\0' + vaultId).digest('hex');
}

const identity = (owner, vaultId) => ({ _id: documentId(owner, vaultId), owner, vaultId });

exports.list = async function (owner) {
    assertSupported();
    return repository.findAll(collection, { filter: { owner, ...LIVE }, projection: { 'envelope.ct': 0 } });
};

// Live vault only; tombstones read as absent.
exports.findOne = async function (owner, vaultId) {
    assertSupported();
    return repository.findOne(collection, { filter: { ...identity(owner, vaultId), ...LIVE } });
};

// Live vault or tombstone (used to continue revisions across delete/re-create).
exports.findAny = async function (owner, vaultId) {
    assertSupported();
    return repository.findOne(collection, { filter: identity(owner, vaultId) });
};

exports.count = async function (owner) {
    assertSupported();
    return repository.count(collection, { filter: { owner, ...LIVE } });
};

// Returns false when the (owner, vaultId) document (live or tombstone) already exists.
exports.insert = async function ({ owner, vaultId, revision, envelope, size, updatedAt }) {
    assertSupported();
    return repository.insertOneExclusive(collection, {
        document: { ...identity(owner, vaultId), revision, envelope, size, updatedAt }
    });
};

// Re-create over a tombstone: one atomic update conditioned on the tombstone's
// revision, so revisions keep increasing across delete/re-create (no ABA).
exports.revive = async function (owner, vaultId, tombstoneRevision, { revision, envelope, size, updatedAt } = {}) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { ...identity(owner, vaultId), revision: tombstoneRevision, envelope: null },
        update: { revision, envelope, size, updatedAt }
    });
};

// Single atomic update of a live vault conditioned on the expected revision; null on mismatch.
exports.compareAndSet = async function (owner, vaultId, expectedRevision, { revision, envelope, size, updatedAt } = {}) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { ...identity(owner, vaultId), revision: expectedRevision, ...LIVE },
        update: { revision, envelope, size, updatedAt }
    });
};

// Delete = single atomic conversion of a live vault into a ciphertext-free tombstone
// that keeps the revision counter (expected + 1); null on mismatch.
exports.compareAndDelete = async function (owner, vaultId, expectedRevision, { updatedAt } = {}) {
    assertSupported();
    return repository.findOneAndUpdate(collection, {
        filter: { ...identity(owner, vaultId), revision: expectedRevision, ...LIVE },
        update: { revision: expectedRevision + 1, envelope: null, size: 0, updatedAt }
    });
};

// Per-user quota document: `ids` = live or in-flight vault ids (at most maxLive),
// `names` = distinct vault names ever created (bounds tombstones). One atomic
// conditional upsert; null when the id is already reserved or a limit is reached.
exports.reserveSlot = async function (owner, vaultId, { newName, maxLive, maxNames } = {}) {
    assertSupported();
    return repository.reserveSlot(quotas, { filter: { _id: owner }, update: { vaultId, newName, maxLive, maxNames } });
};

exports.releaseSlot = async function (owner, vaultId, { newName } = {}) {
    assertSupported();
    return repository.releaseSlot(quotas, { filter: { _id: owner }, update: { vaultId, newName } });
};

exports.findQuota = async function (owner) {
    assertSupported();
    return repository.findOne(quotas, { filter: { _id: owner } });
};
