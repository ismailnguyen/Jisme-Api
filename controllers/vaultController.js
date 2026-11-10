'use strict';
// HTTP boundary for client vault envelopes. See docs/vault-envelope-design.md.
const vaultService = require('../services/vaultService.js');
const rateLimit = require('../services/vaultRateLimit.js');
const { verifyAccessToken } = require('../utils/credentials.js');
const { throwError, generateError } = require('../utils/errors.js');

const RECENT_AUTH_MS = 300000; // destructive operations (delete, replace) need auth_time within 5 minutes
const MAPPED_STATUS = [400, 401, 403, 404, 409, 413, 429, 503];
const REVISION_QUERY = /^(0|[1-9][0-9]{0,15})$/;

// Same rule as generateFreshSessionResolver: only fully authenticated sessions
// carrying a deliberate auth_time claim. Pre-auth and legacy tokens must sign in again.
async function resolveSession(headers) {
    let session = null;
    try {
        session = await verifyAccessToken(headers && headers.authorization);
    } catch (_) {
        session = null;
    }
    if (!session || session.isAuthorized !== true || typeof session.uuid !== 'string' || !session.uuid
        || !Number.isSafeInteger(session.auth_time)) {
        throw generateError('Unauthorized', 'A fully authenticated session is required; sign in again.', 401);
    }
    return session;
}

function assertRecentAuthentication(session, now = Date.now()) {
    const age = now - session.auth_time * 1000;
    if (age < 0 || age >= RECENT_AUTH_MS) {
        throw generateError('Reauthentication required', 'Sign in again to replace or delete a vault.', 401);
    }
}

// Only deliberate service errors map to their status; anything else is a
// generic 503 so driver/connection details never reach the client.
function failure(error) {
    if (!error || typeof error.toJSON !== 'function' || !MAPPED_STATUS.includes(error.code)) {
        return throwError(generateError('Vault storage unavailable', 'Try again later.', 503));
    }
    const response = throwError(error);
    if (error.code === 409) {
        response.data.currentRevision = Number.isSafeInteger(error.currentRevision) ? error.currentRevision : 0;
    }
    if (error.code === 429) {
        const seconds = Number.isSafeInteger(error.retryAfterSeconds)
            && error.retryAfterSeconds >= 1 && error.retryAfterSeconds <= 60
            ? error.retryAfterSeconds : 60;
        response.headers = { 'Retry-After': String(seconds) };
    }
    return response;
}

const list = async function (session) {
    return { status: 200, data: { vaults: await vaultService.list(session.uuid) } };
};

const get = async function (session, params) {
    return { status: 200, data: await vaultService.get(session.uuid, params && params.vaultId) };
};

// Creating a new vault (expectedRevision 0) destroys nothing. Anything else may
// replace an existing vault with arbitrary bytes, which is as destructive as a
// delete, so it needs the same recent sign-in (fail closed for malformed bodies).
const put = async function (session, params, body) {
    const isCreate = body !== null && typeof body === 'object' && body.expectedRevision === 0;
    if (!isCreate) {
        assertRecentAuthentication(session);
    }
    const { created, ...result } = await vaultService.put(session.uuid, params && params.vaultId, body);
    return { status: created ? 201 : 200, data: result };
};

const remove = async function (session, params, query) {
    assertRecentAuthentication(session);
    const raw = query && query.expectedRevision;
    if (typeof raw !== 'string' || !REVISION_QUERY.test(raw)) {
        throw generateError('Invalid vault input', 'expectedRevision query parameter must be a positive integer', 400);
    }
    return { status: 200, data: await vaultService.remove(session.uuid, params && params.vaultId, Number(raw)) };
};

// Authenticate first (unauthenticated callers get 401 without the server walking
// their payload), then the same guard as the user endpoints: PRF inputs/outputs
// are client-side vault unlock material and are refused anywhere in the inputs
// the handler receives (params; body for PUT; query for DELETE).
// Per-owner rate limiting runs after authentication (the key is the owner hash
// of the verified session) and before anything else, so no storage, quota or
// validation work happens for a flooded caller. Fail closed: the limiter cannot
// be disabled and denies on any internal fault.
const guarded = (handler, kind) => async (headers, ...inputs) => {
    let session;
    try {
        session = await resolveSession(headers);
    } catch (error) {
        return failure(error);
    }
    const verdict = rateLimit.consume(vaultService.ownerOf(session.uuid), kind);
    if (!verdict.allowed) {
        const error = generateError('Too many vault requests', 'Rate limit exceeded; try again later.', 429);
        error.retryAfterSeconds = verdict.retryAfterSeconds;
        return failure(error);
    }
    try {
        inputs.forEach((input) => require('../services/webauthnVerifier.js').assertNoPRF(input));
    } catch (_) {
        return throwError(generateError('Invalid vault payload', 'PRF material must remain on the client for vault unlock.', 400));
    }
    try {
        return await handler(session, ...inputs);
    } catch (error) {
        return failure(error);
    }
};

exports.list = guarded(list, 'read');
exports.get = guarded(get, 'read');
exports.put = guarded(put, 'write');
exports.remove = guarded(remove, 'write');
