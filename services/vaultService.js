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
    MAX_VAULTS_PER_USER: 8,         // hard bound: atomic per-user quota reservation
    MAX_VAULT_NAMES: 64,            // distinct names ever created (bounds tombstones)
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

// currentRevision is read separately (not atomically with the failed write), so
// it is only a hint: clients must re-fetch before retrying.
async function conflict(owner, vaultId) {
    const current = await storage(() => repository.findOne(owner, vaultId));
    const error = generateError('Revision conflict', 'The vault changed; fetch the latest revision, merge locally and retry.', 409);
    error.currentRevision = current && Number.isSafeInteger(current.revision) ? current.revision : 0;
    return error;
}

const isTombstone = (doc) => doc.envelope == null;

// Releasing a quota slot after the vault write is already settled: a failure
// only leaves the slot held (fail closed: the limit gets stricter, never looser).
async function releaseQuietly(owner, vaultId, newName) {
    try {
        await repository.releaseSlot(owner, vaultId, { newName });
    } catch (_) {
        // intentionally ignored; see above
    }
}

// Reservation refused: the id is already held (live or in-flight) -> 409,
// otherwise a limit was reached -> 403.
async function quotaRefusal(owner, vaultId, newName) {
    const quota = await storage(() => repository.findQuota(owner));
    if (quota && Array.isArray(quota.ids) && quota.ids.includes(vaultId)) {
        return conflict(owner, vaultId);
    }
    if (newName && quota && Number.isSafeInteger(quota.names) && quota.names >= LIMITS.MAX_VAULT_NAMES) {
        return generateError('Vault name limit reached',
            `At most ${LIMITS.MAX_VAULT_NAMES} distinct vault names per user; re-use a deleted vault name.`, 403);
    }
    return generateError('Vault limit reached', `At most ${LIMITS.MAX_VAULTS_PER_USER} vaults per user.`, 403);
}

// Create (expectedRevision 0). A deleted vault leaves a tombstone holding its last
// revision, and re-creating it continues from there, so a stale writer's revision
// can never match a re-created vault (no ABA). The per-user slot is reserved
// atomically before the write, so concurrent creates cannot exceed the limit.
async function create(owner, vaultId, { envelope, size, updatedAt }) {
    const existing = await storage(() => repository.findAny(owner, vaultId));
    if (existing && !isTombstone(existing)) {
        throw await conflict(owner, vaultId);
    }
    const newName = !existing;
    const revision = newName ? 1 : existing.revision + 1;
    if (!Number.isSafeInteger(revision) || revision < 1 || !Number.isSafeInteger(revision + 1)) {
        throw await conflict(owner, vaultId);
    }

    const reserved = await storage(() => repository.reserveSlot(owner, vaultId,
        { newName, maxLive: LIMITS.MAX_VAULTS_PER_USER, maxNames: LIMITS.MAX_VAULT_NAMES }));
    if (!reserved) {
        throw await quotaRefusal(owner, vaultId, newName);
    }

    // On a storage error the write may have landed, so the slot is kept (fail closed).
    const written = await storage(() => (newName
        ? repository.insert({ owner, vaultId, revision, envelope, size, updatedAt })
        : repository.revive(owner, vaultId, existing.revision, { revision, envelope, size, updatedAt })));
    if (!written) {
        await releaseQuietly(owner, vaultId, newName);
        throw await conflict(owner, vaultId);
    }
    return { created: true, vaultId, revision, updatedAt };
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
        return create(owner, vaultId, { envelope, size, updatedAt });
    }

    const revision = expectedRevision + 1;
    const updated = await storage(() => repository.compareAndSet(owner, vaultId, expectedRevision, { revision, envelope, size, updatedAt }));
    if (!updated) {
        throw await conflict(owner, vaultId);
    }
    return { created: false, vaultId, revision, updatedAt };
};

// Delete leaves a ciphertext-free tombstone (revision expected + 1), then frees the slot.
const remove = async function (uuid, vaultId, expectedRevision, now = new Date()) {
    const owner = ownerOf(uuid);
    validateVaultId(vaultId);
    validateRevision(expectedRevision, 1);
    const deleted = await storage(() => repository.compareAndDelete(owner, vaultId, expectedRevision, { updatedAt: now.toISOString() }));
    if (!deleted) {
        throw await conflict(owner, vaultId);
    }
    await releaseQuietly(owner, vaultId, false);
    return { vaultId, deleted: true };
};

exports.LIMITS = LIMITS;
exports.ownerOf = ownerOf;
exports.list = list;
exports.get = get;
exports.put = put;
exports.remove = remove;
