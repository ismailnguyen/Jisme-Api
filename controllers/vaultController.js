'use strict';
// HTTP boundary for client vault envelopes. See docs/vault-envelope-design.md.
const vaultService = require('../services/vaultService.js');
const { verifyAccessToken } = require('../utils/credentials.js');
const { throwError, generateError } = require('../utils/errors.js');

const RECENT_AUTH_MS = 300000; // destructive operations need auth_time within 5 minutes
const MAPPED_STATUS = [400, 401, 403, 404, 409, 413, 503];
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
        throw generateError('Reauthentication required', 'Sign in again to delete a vault.', 401);
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
    return response;
}

const list = async function (headers) {
    try {
        const { uuid } = await resolveSession(headers);
        return { status: 200, data: { vaults: await vaultService.list(uuid) } };
    } catch (error) {
        return failure(error);
    }
};

const get = async function (headers, params) {
    try {
        const { uuid } = await resolveSession(headers);
        return { status: 200, data: await vaultService.get(uuid, params && params.vaultId) };
    } catch (error) {
        return failure(error);
    }
};

const put = async function (headers, params, body) {
    try {
        const { uuid } = await resolveSession(headers);
        const { created, ...result } = await vaultService.put(uuid, params && params.vaultId, body);
        return { status: created ? 201 : 200, data: result };
    } catch (error) {
        return failure(error);
    }
};

const remove = async function (headers, params, query) {
    try {
        const session = await resolveSession(headers);
        assertRecentAuthentication(session);
        const raw = query && query.expectedRevision;
        if (typeof raw !== 'string' || !REVISION_QUERY.test(raw)) {
            throw generateError('Invalid vault input', 'expectedRevision query parameter must be a positive integer', 400);
        }
        return { status: 200, data: await vaultService.remove(session.uuid, params && params.vaultId, Number(raw)) };
    } catch (error) {
        return failure(error);
    }
};

// Same guard as the user endpoints: PRF inputs/outputs are client-side vault
// unlock material and are refused anywhere in params, body or query.
const withoutPRF = (handler) => async (headers, ...inputs) => {
    try {
        inputs.forEach((input) => require('../services/webauthnVerifier.js').assertNoPRF(input));
    } catch (_) {
        return throwError(generateError('Invalid vault payload', 'PRF material must remain on the client for vault unlock.', 400));
    }
    return handler(headers, ...inputs);
};

exports.list = withoutPRF(list);
exports.get = withoutPRF(get);
exports.put = withoutPRF(put);
exports.remove = withoutPRF(remove);
