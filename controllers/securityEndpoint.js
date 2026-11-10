'use strict';
// HTTP boundary shared by the passkey and recovery endpoints.
// Order (same as the vault endpoints): session first (401 without walking the
// payload), then the per-user rate limit (429), then the PRF guard on every
// input the handler receives (400), then the handler.
const { assertNoPRF } = require('../services/webauthnVerifier.js');
const { enforceRateLimit } = require('../services/sessionPolicy.js');
const { throwError, generateError } = require('../utils/errors.js');

const MAPPED_STATUS = [400, 401, 403, 404, 409, 429, 503];

// Only deliberate service errors map to their status; anything else is a
// generic 503 so internal details never reach the client.
function failure(error) {
    if (!error || typeof error.toJSON !== 'function' || !MAPPED_STATUS.includes(error.code)) {
        return throwError(generateError('Service unavailable', 'Try again later.', 503));
    }
    const response = throwError(error);
    if (error.code === 429) {
        const seconds = Number.isSafeInteger(error.retryAfterSeconds)
            && error.retryAfterSeconds >= 1 && error.retryAfterSeconds <= 60 ? error.retryAfterSeconds : 60;
        response.headers = { 'Retry-After': String(seconds) };
    }
    return response;
}

const prfRefused = () => throwError(generateError('Invalid user payload', 'PRF material must remain on the client for vault unlock.', 400));

exports.endpoint = function ({ resolve, rateKind, handler }) {
    return async (headers, ...inputs) => {
        let session;
        try {
            session = await resolve(headers);
        } catch (error) {
            return failure(error);
        }
        try {
            enforceRateLimit(session.uuid, rateKind);
        } catch (error) {
            return failure(error);
        }
        try {
            inputs.forEach((input) => assertNoPRF(input));
        } catch (_) {
            return prfRefused();
        }
        try {
            return await handler(session, ...inputs);
        } catch (error) {
            return failure(error);
        }
    };
};

exports.failure = failure;
