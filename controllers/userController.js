'use strict';

const userService = require('../services/userService.js');
const {
	verifyAccessToken,
} = require('../utils/credentials.js');
const { throwError, generateError } = require('../utils/errors.js');

// Client (agent, referer, ip) is required here to prevent CSRF attacks
const login = async function({ email }, { agent, referer, ip }) {
	try {
		const user = await userService.requestLogin(
			email,
			{ agent, referer, ip}
		);
	
		return {
			status: 200,
			data: user
		};
	}
	catch (error) {
		return throwError(error);
	}
}

// Client (agent, referer, ip) is required here to log login activities
const verifyPassword = async function({ authorization }, { password, isExtendedSession }, { agent, referer, ip }) {
	try {
		const { uuid } = await verifyAccessToken(authorization);

		// No need to verify step here as we can provide password from different step
		if (!uuid) {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const user = await userService.verifyPassword(
				uuid,
				password,
				isExtendedSession,
				{ agent, referer, ip }
			);
	
			return {
				status: 200,
				data: user
			};
		}
		catch (error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

const verifyOTP = async function ({ authorization }, { totpToken, isExtendedSession }, { agent, referer, ip }) {
	try {
		const { email, uuid, step } = await verifyAccessToken(authorization);

		// The step should be request_otp, otherwise reject
		if (!uuid || !email || step !== 'request_otp') {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const user = await userService.verifyOTP(
				{ email, uuid },
				isExtendedSession,
				totpToken,
				{ agent, referer, ip }
			);
		
			return {
				status: 200,
				data: user
			};
		}
		catch (error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

// Real passkey login (P1). The legacy identifier-only payload ({passkey: {id}})
// and anything that is not a full {challenge, response} ceremony gets the
// re-enrollment 403 before the service is touched.
const verifyPasskey = async function ({ authorization } = {}, payload, { agent, referer, ip } = {}) {
	try {
		const { email, uuid } = await verifyAccessToken(authorization);

		if (!uuid) {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		if (!payload || typeof payload.challenge !== 'string' || !payload.response || typeof payload.response !== 'object') {
			throw generateError('Passkey re-enrollment required',
				'Sign in with password (and MFA if enabled), then re-enroll your passkey via verified enrollment.', 403);
		}

		const user = await userService.verifyPasskey(
			{ email, uuid },
			payload,
			{ agent, referer, ip }
		);

		return {
			status: 200,
			data: user
		};
	}
	catch (error) {
		const response = throwError(error && typeof error.toJSON === 'function'
			? error
			: generateError('Error', 'Passkey login failed.', 500));
		if (error && error.code === 429) {
			response.headers = { 'Retry-After': String(error.retryAfterSeconds || 60) };
		}
		return response;
	}
}

const register = async function({ email, password }) {
	try {
		const user = await userService.register(
			{
				email: email,
				password: password
			},
			client
		);
	
		return {
			status: 201,
			data: user
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const update = async function({ authorization }, payload) {
	try {
		const { email, uuid, isAuthorized } = await verifyAccessToken(authorization);

		if (!isAuthorized) {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const updatedUser = await userService.update(
				{
					email: email,
					uuid: uuid,
				},
				{
					password: payload.password,
					last_update_date: new Date().toISOString(), // Update last update date at each update
					avatarUrl: payload.avatarUrl,
					passkeys: payload.passkeys
				}
			);

			return {
				status: 200,
				data: updatedUser
			};
		}
		catch(error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

const getInformation = async function({ authorization }) {
	try {
		const { email, uuid, isAuthorized } = await verifyAccessToken(authorization);

		if (!isAuthorized) {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const getInformation = await userService.getInformation(
				{
					email: email,
					uuid: uuid,
				}
			);

			return {
				status: 200,
				data: getInformation
			};
		}
		catch(error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

// Authentication and vault unlock are distinct protocols. Never accept PRF
// output on any user write/auth endpoint, even if the handler ignores the field.
const withoutPRF = (handler, payloadIndex) => async (...args) => {
    try {
        require('../services/webauthnVerifier.js').assertNoPRF(args[payloadIndex]);
    } catch (_) {
        return throwError(generateError('Invalid user payload', 'PRF material must remain on the client for vault unlock.', 400));
    }
    return handler(...args);
};
exports.login = withoutPRF(login, 0);
exports.verifyPassword = withoutPRF(verifyPassword, 1);
exports.verifyPasskey = withoutPRF(verifyPasskey, 1);
exports.verifyOTP = withoutPRF(verifyOTP, 1);
exports.register = withoutPRF(register, 0);
exports.update = withoutPRF(update, 1);
exports.getInformation = getInformation;
