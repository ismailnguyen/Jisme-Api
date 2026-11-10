'use strict';
// Shared guard + key derivation for the string-_id atomic collections
// (see repository/adapters/dbAdapter.js ATOMIC_COLLECTIONS).
const { createHash } = require('node:crypto');
const { db_repository_type, node_env } = require('../utils/config.js');

// Allowlist (fail closed): only the Mongo adapter provides exclusive insert and
// single-document compare-and-set. The in-memory mock is for tests/dev only.
exports.assertSupported = function () {
    const supported = db_repository_type === 'db'
        || (db_repository_type === 'mock' && node_env !== 'production');
    if (!supported) {
        throw new Error('Security collections require the Mongo repository');
    }
};

// Domain-separated SHA-256 (hex). Used so raw uuids / credential ids never
// become storage keys and keys from different domains can never collide.
exports.keyOf = function (domain, value) {
    if (typeof value !== 'string' || !value) throw new Error('Invalid key material');
    return createHash('sha256').update(domain + '\0' + value).digest('hex');
};
