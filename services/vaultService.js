'use strict';
// Client vault envelope storage. The server only ever handles opaque,
// client-encrypted envelopes: no plaintext, keys or derivation material, and
// no fallback to server-held secrets. See docs/vault-envelope-design.md.
const { createHash } = require('node:crypto');
const repository = require('../repository/vaultEnvelopeRepository.js');
const { generateError } = require('../utils/errors.js');

const LIMITS = Object.freeze({
    ENVELOPE_VERSION: 1,
    MIN_CIPHERTEXT_BYTES: 28,       // at least an AEAD nonce + tag
    MAX_CIPHERTEXT_BYTES: 524288,   // 512 KiB
    MAX_VAULTS_PER_USER: 8,         // soft bound (checked before insert)
});
const VAULT_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const WRITE_KEYS = ['envelope', 'expectedRevision'];
const ENVELOPE_KEYS = ['ct', 'v'];

const invalid = (reason) => generateError('Invalid vault input', reason, 400);

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));

const onlyKeys = (value, allowed) => Object.keys(value).every((key) => allowed.includes(key));

// Owner key comes from the verified session uuid only. Domain-separated hash:
// the raw uuid is not stored and no server secret is involved.
function ownerOf(uuid) {
    if (typeof uuid !== 'string' || !uuid) {
        throw generateError('Unauthorized', 'Invalid session.', 401);
    }
    return createHash('sha256').update('jisme.vault.owner.v1\0' + uuid).digest('hex');
}

function validateVaultId(vaultId) {
    if (typeof vaultId !== 'string' || !VAULT_ID.test(vaultId)) {
        throw invalid('vaultId must match ' + VAULT_ID.source);
    }
}

function validateRevision(revision, minimum) {
    if (!Number.isSafeInteger(revision) || revision < minimum || !Number.isSafeInteger(revision + 1)) {
        throw invalid(`expectedRevision must be an integer >= ${minimum}`);
    }
    return revision;
}

function validateEnvelope(envelope) {
    if (!isPlainObject(envelope)) {
        throw invalid('envelope must be an object');
    }
    if (!onlyKeys(envelope, ENVELOPE_KEYS)) {
        throw invalid('Unknown envelope field; only {v, ct} are accepted');
    }
    if (envelope.v !== LIMITS.ENVELOPE_VERSION) {
        throw invalid('Unsupported envelope version');
    }
    const { ct } = envelope;
    if (typeof ct !== 'string' || !BASE64URL.test(ct)) {
        throw invalid('ct must be unpadded base64url');
    }
    // Bound before decoding so oversized input is never materialised twice.
    if (Math.floor(ct.length * 3 / 4) > LIMITS.MAX_CIPHERTEXT_BYTES) {
        throw generateError('Envelope too large', `ct must be at most ${LIMITS.MAX_CIPHERTEXT_BYTES} bytes`, 413);
    }
    const decoded = Buffer.from(ct, 'base64url');
    if (decoded.toString('base64url') !== ct) {
        throw invalid('ct must be canonical base64url');
    }
    if (decoded.length < LIMITS.MIN_CIPHERTEXT_BYTES) {
        throw invalid(`ct must be at least ${LIMITS.MIN_CIPHERTEXT_BYTES} bytes`);
    }
    return { envelope: { v: LIMITS.ENVELOPE_VERSION, ct }, size: decoded.length };
}

function validateWriteBody(body) {
    if (!isPlainObject(body) || !onlyKeys(body, WRITE_KEYS)) {
        throw invalid('Body must be exactly {expectedRevision, envelope}');
    }
    return { expectedRevision: validateRevision(body.expectedRevision, 0), ...validateEnvelope(body.envelope) };
}

// Storage failures never leak driver details and never fall back.
async function storage(operation) {
    try {
        return await operation();
    } catch (_) {
        throw generateError('Vault storage unavailable', 'Try again later.', 503);
    }
}

async function conflict(owner, vaultId) {
    const current = await storage(() => repository.findOne(owner, vaultId));
    const error = generateError('Revision conflict', 'The vault changed; fetch the latest revision, merge locally and retry.', 409);
    error.currentRevision = current && Number.isSafeInteger(current.revision) ? current.revision : 0;
    return error;
}

const list = async function (uuid) {
    const owner = ownerOf(uuid);
    const documents = await storage(() => repository.list(owner));
    return documents.map((doc) => ({
        vaultId: doc.vaultId,
        revision: doc.revision,
        size: doc.size,
        v: doc.envelope && doc.envelope.v,
        updatedAt: doc.updatedAt,
    }));
};

const get = async function (uuid, vaultId) {
    const owner = ownerOf(uuid);
    validateVaultId(vaultId);
    const doc = await storage(() => repository.findOne(owner, vaultId));
    if (!doc) {
        throw generateError('Not found', 'Vault not found.', 404);
    }
    return {
        vaultId: doc.vaultId,
        revision: doc.revision,
        updatedAt: doc.updatedAt,
        envelope: { v: doc.envelope.v, ct: doc.envelope.ct },
    };
};

const put = async function (uuid, vaultId, body, now = new Date()) {
    const owner = ownerOf(uuid);
    validateVaultId(vaultId);
    const { expectedRevision, envelope, size } = validateWriteBody(body);
    const updatedAt = now.toISOString();

    if (expectedRevision === 0) {
        const count = await storage(() => repository.count(owner));
        if (!Number.isSafeInteger(count)) {
            throw generateError('Vault storage unavailable', 'Try again later.', 503);
        }
        if (count >= LIMITS.MAX_VAULTS_PER_USER) {
            throw generateError('Vault limit reached', `At most ${LIMITS.MAX_VAULTS_PER_USER} vaults per user.`, 403);
        }
        const inserted = await storage(() => repository.insert({ owner, vaultId, revision: 1, envelope, size, updatedAt }));
        if (!inserted) {
            throw await conflict(owner, vaultId);
        }
        return { created: true, vaultId, revision: 1, updatedAt };
    }

    const revision = expectedRevision + 1;
    const updated = await storage(() => repository.compareAndSet(owner, vaultId, expectedRevision, { revision, envelope, size, updatedAt }));
    if (!updated) {
        throw await conflict(owner, vaultId);
    }
    return { created: false, vaultId, revision, updatedAt };
};

const remove = async function (uuid, vaultId, expectedRevision) {
    const owner = ownerOf(uuid);
    validateVaultId(vaultId);
    validateRevision(expectedRevision, 1);
    const deleted = await storage(() => repository.compareAndDelete(owner, vaultId, expectedRevision));
    if (!deleted) {
        throw await conflict(owner, vaultId);
    }
    return { vaultId, deleted: true };
};

exports.LIMITS = LIMITS;
exports.list = list;
exports.get = get;
exports.put = put;
exports.remove = remove;
