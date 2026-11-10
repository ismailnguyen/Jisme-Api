'use strict';
const { randomBytes } = require('node:crypto');
const repository = require('./ports/repositoryPort.js');
const collection = 'webauthn_challenges';
const TTL_MS = 300000; // upper bound; callers may ask for a shorter TTL
const PURPOSES = ['authentication', 'registration', 'vault-unlock'];

exports.issue = async function (userId, purpose, now = Date.now(), ttlMs = TTL_MS) {
    if (!userId || !PURPOSES.includes(purpose) || !Number.isSafeInteger(now)
        || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > TTL_MS) {
        throw new Error('Invalid challenge binding');
    }
    const challenge = randomBytes(32).toString('base64url');
    await repository.insertOne(collection, {
        document: { challenge, userId, purpose, expiresAt: now + ttlMs }
    });
    return challenge;
};

exports.consume = async function (challenge, userId, purpose, now = Date.now()) {
    if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)
        || typeof userId !== 'string' || !PURPOSES.includes(purpose)
        || !Number.isSafeInteger(now)) {
        return null;
    }
    return repository.findOneAndDelete(collection, {
        filter: { challenge, userId, purpose, expiresAt: { $gt: now } }
    });
};
