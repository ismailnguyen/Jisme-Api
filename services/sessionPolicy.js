'use strict';
// Session requirements for the security-sensitive user endpoints.
//
//   preAuthenticated : any valid token carrying a uuid (POST users/login result).
//                      Used only to bind passkey-login challenges to a user; the
//                      WebAuthn assertion is the actual proof.
//   authenticated    : full session (isAuthorized + integer auth_time).
//   passwordSession  : authenticated AND amr contains 'pwd' (+ 'otp' when the
//                      user has MFA enabled). Passkey-only sessions cannot
//                      manage passkeys or use recovery.
//   fresh            : auth_time within the last 5 minutes (not in the future).
const { verifyAccessToken } = require('../utils/credentials.js');
const { findOne: findUser } = require('../repository/userRepository.js');
const { encrypt } = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');
const { keyOf } = require('../repository/atomicSupport.js');
const rateLimit = require('./vaultRateLimit.js');

const RECENT_AUTH_MS = 300000;

const unauthorized = (reason) => generateError('Unauthorized', reason, 401);

async function verified(headers) {
    try {
        return await verifyAccessToken(headers && headers.authorization);
    } catch (_) {
        throw unauthorized('A valid session is required; sign in again.');
    }
}

exports.preAuthenticated = async function (headers) {
    const session = await verified(headers);
    if (!session || typeof session.uuid !== 'string' || !session.uuid) {
        throw unauthorized('A valid session is required; sign in again.');
    }
    return session;
};

exports.authenticated = async function (headers) {
    const session = await verified(headers);
    if (!session || session.isAuthorized !== true || typeof session.uuid !== 'string' || !session.uuid
        || !Number.isSafeInteger(session.auth_time)) {
        throw unauthorized('A fully authenticated session is required; sign in again.');
    }
    return session;
};

exports.passwordSession = async function (headers, { fresh = true, now = Date.now() } = {}) {
    const session = await exports.authenticated(headers);
    const amr = Array.isArray(session.amr) ? session.amr : [];
    if (!amr.includes('pwd')) {
        throw unauthorized('Sign in with your password (and MFA if enabled) to continue.');
    }
    if (fresh) {
        const age = now - session.auth_time * 1000;
        if (age < 0 || age >= RECENT_AUTH_MS) {
            throw generateError('Reauthentication required', 'Sign in again with your password (and MFA if enabled).', 401);
        }
    }
    let user = null;
    try {
        user = await findUser({ query: { uuid: encrypt(session.uuid) } });
    } catch (_) {
        user = null;
    }
    if (!user) {
        throw unauthorized('User not found.');
    }
    if (user.isMFAEnabled && !amr.includes('otp')) {
        throw unauthorized('MFA verification is required for this operation; sign in again.');
    }
    return { ...session, user };
};

// Same fail-closed fixed-window limiter as the vault endpoints, keyed by a
// domain-separated hash of the uuid ('sensitive' and 'recovery' budgets).
exports.enforceRateLimit = function (uuid, kind) {
    let verdict;
    try {
        verdict = rateLimit.consume(keyOf('jisme.ratelimit.user.v1', uuid), kind);
    } catch (_) {
        verdict = { allowed: false, retryAfterSeconds: 60 };
    }
    if (!verdict.allowed) {
        const error = generateError('Too many requests', 'Rate limit exceeded; try again later.', 429);
        error.retryAfterSeconds = verdict.retryAfterSeconds;
        throw error;
    }
};

exports.RECENT_AUTH_MS = RECENT_AUTH_MS;
