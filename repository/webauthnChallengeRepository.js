'use strict';
const { randomBytes } = require('node:crypto');
const repository = require('./ports/repositoryPort.js');
const collection = 'webauthn_challenges';
const TTL_MS = 300000;

exports.issue = async function (userId, purpose, now = Date.now()) {
    if (!userId || !['authentication', 'registration'].includes(purpose) || !Number.isSafeInteger(now)) {
        throw new Error('Invalid challenge binding');
    }
    const challenge = randomBytes(32).toString('base64url');
    await repository.insertOne(collection, {
        document: { challenge, userId, purpose, expiresAt: now + TTL_MS }
    });
    return challenge;
};

exports.consume = async function (challenge, userId, purpose, now = Date.now()) {
    if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)
        || typeof userId !== 'string' || !['authentication', 'registration'].includes(purpose)
        || !Number.isSafeInteger(now)) {
        return null;
    }
    return repository.findOneAndDelete(collection, {
        filter: { challenge, userId, purpose, expiresAt: { $gt: now } }
    });
};
