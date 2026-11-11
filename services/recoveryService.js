'use strict';
// One-time recovery codes.
//
// INVARIANT — RECOVERY CANNOT RESTORE VAULT CONTENTS. Vault envelopes are
// encrypted on the client under keys derived from the user's unlock secret
// (phrase and/or passkey PRF). The server never holds those keys, the recovery
// code is not a key-encryption key, and nothing here reads, decrypts,
// re-encrypts or returns envelope data. If every unlock secret is lost, the
// vault ciphertext is unrecoverable by design; recovery only re-establishes
// control of the account so the user can set a new unlock secret (a new,
// empty vault) and enroll new passkeys.
//
// Storage: only a salted scrypt hash (per-record random salt) is kept; the
// plaintext code is returned exactly once (at issuance / rotation). Codes are
// 160-bit random, so the hash is not brute-forceable; scrypt is defence in depth.
// Use is one-time: a successful verification rotates the hash with a
// compare-and-set, so concurrent reuse of the same code fails.
const { randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const repository = require('../repository/recoveryCodeRepository.js');
const credentials = require('../repository/webauthnCredentialRepository.js');
const unlockState = require('../repository/vaultUnlockRepository.js');
const { updateOne: updateUser } = require('../repository/userRepository.js');
const { encrypt } = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');
const audit = require('./auditLog.js');

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32
const CODE_CHARS = 32;                                 // 20 random bytes
const CODE_PATTERN = new RegExp(`^[${ALPHABET}]{${CODE_CHARS}}$`);
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const ALGO = 'scrypt';
const ACTIONS = Object.freeze(['reset_unlock', 'reenroll_passkeys']);
const NOTICE = 'Recovery cannot restore vault contents: data encrypted under a lost unlock secret is unrecoverable. '
    + 'Store this new recovery code safely; it is shown only once.';

function generateCode() {
    const bytes = randomBytes(20);
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    return out.match(/.{4}/g).join('-');
}

function normalize(input) {
    if (typeof input !== 'string' || input.length > 128) return null;
    const value = input.toUpperCase().replace(/[\s-]/g, '');
    return CODE_PATTERN.test(value) ? value : null;
}

function derive(normalized, salt) {
    return new Promise((resolve, reject) => {
        scrypt(normalized, Buffer.from(salt, 'base64url'), 32, SCRYPT, (error, key) => (error ? reject(error) : resolve(key)));
    });
}

async function newRecord() {
    const code = generateCode();
    const salt = randomBytes(16).toString('base64url');
    const hash = (await derive(normalize(code), salt)).toString('base64url');
    return { code, record: { algo: ALGO, salt, hash } };
}

async function storage(operation) {
    try {
        return await operation();
    } catch (_) {
        throw generateError('Recovery unavailable', 'Try again later.', 503);
    }
}

// Issues a code only if the user has none. Returns the plaintext code (once) or null.
const issueIfAbsent = async function (uuid, client) {
    const { code, record } = await newRecord();
    const inserted = await storage(() => repository.insertIfAbsent(uuid, { ...record, createdAt: new Date().toISOString() }));
    if (!inserted) return null;
    await audit.record(uuid, 'recovery_code_issued', client);
    return code;
};

// Issues a new code, replacing any existing one (the previous code stops
// working). Shown exactly once, so a user who lost theirs can get another.
const issue = async function (uuid, client) {
    const code = await issueIfAbsent(uuid, client);
    if (code) return { recoveryCode: code, notice: NOTICE };

    const stored = await storage(() => repository.find(uuid));
    const { code: nextCode, record } = await newRecord();
    const rotated = stored && await storage(() => repository.rotate(uuid, stored.hash, { ...record, rotatedAt: new Date().toISOString() }));
    if (!rotated) {
        throw generateError('Recovery unavailable', 'The recovery code changed concurrently; try again.', 409);
    }
    await audit.record(uuid, 'recovery_code_rotated', client);
    return { recoveryCode: nextCode, notice: NOTICE, replaced: true };
};

const verify = async function (uuid, body, client) {
    const input = body !== null && typeof body === 'object' ? body : {};
    if (!ACTIONS.includes(input.action)) {
        throw generateError('Invalid recovery input', `action must be one of ${ACTIONS.join(', ')}.`, 400);
    }
    const normalized = normalize(input.recoveryCode);
    if (!normalized) {
        throw generateError('Invalid recovery input', 'Malformed recovery code.', 400);
    }
    const failed = async () => {
        await audit.record(uuid, 'recovery_failed', client);
        return generateError('Unauthorized', 'Invalid recovery code.', 401);
    };
    const stored = await storage(() => repository.find(uuid));
    if (!stored || stored.algo !== ALGO || typeof stored.salt !== 'string' || typeof stored.hash !== 'string') {
        await derive(normalized, randomBytes(16).toString('base64url')); // similar timing when absent
        throw await failed();
    }
    const expected = Buffer.from(stored.hash, 'base64url');
    const actual = await derive(normalized, stored.salt);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        throw await failed();
    }

    // One-time: rotate before any side effect; losing the CAS means reuse.
    const { code: nextCode, record } = await newRecord();
    const rotated = await storage(() => repository.rotate(uuid, stored.hash, { ...record, rotatedAt: new Date().toISOString() }));
    if (!rotated) {
        throw await failed();
    }

    let revokedPasskeys = 0;
    if (input.action === 'reenroll_passkeys') {
        revokedPasskeys = await storage(() => credentials.removeAll(uuid));
        await storage(() => updateUser({ query: { uuid: encrypt(uuid) }, newValue: { hasVerifiedPasskey: false } }));
    }
    // Both actions end any current unlock: the old unlock secret is being replaced.
    await storage(() => unlockState.clear(uuid));
    await audit.record(uuid, 'recovery_used', client);

    const result = { action: input.action, recoveryCode: nextCode, notice: NOTICE };
    if (input.action === 'reenroll_passkeys') result.revokedPasskeys = revokedPasskeys;
    return result;
};

exports.ACTIONS = ACTIONS;
exports.NOTICE = NOTICE;
exports.normalize = normalize;
exports.generateCode = generateCode;
exports.issueIfAbsent = issueIfAbsent;
exports.issue = issue;
exports.verify = verify;
