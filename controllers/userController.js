'use strict';

const userService = require('../services/userService.js');
const {
	verifyToken,
	verifyPasskeyChallenge
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
const verifyPassword = async function({ authorization }, { password }, { agent, referer, ip }) {
	try {
		const { uuid, step } = await verifyToken(authorization);

		// The step should be request_password, otherwise reject
		if (!uuid || step !== 'request_password') {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const user = await userService.verifyPassword(
				uuid,
				password,
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

const requestLoginWithPasskey = async function ({ agent, referer, ip }) {
	try {
		const passkeyOptions = await userService.requestLoginWithPasskey({ 
			agent: agent, 
			referer: referer, 
			ip: ip
		});
	
		return {
			status: 200,
			data: passkeyOptions
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const verifyPasskey = async function ({ passkey, challenge }, client) {
	try {
		if (!passkey || !challenge) {
			throw generateError('Unauthorized', 'Missing passkey/challenge', 401);
		}

		const { agent, referer, ip } = await verifyPasskeyChallenge (challenge);

		//If the one who request the challenge is not the same as the one who is trying to log, reject the request
		if (client.agent !== agent || client.referer !== referer || client.ip !== ip) {
			throw generateError('Unauthorized', 'Invalid passkey challenge', 401);
		}

		// const { uuid, step } = await verifyToken(authorization);

		// // The step should be request_passkey, otherwise reject
		// if (!uuid || step !== 'request_passkey') {
		// 	throw generateError('Unauthorized', 'Invalid session.', 401);
		// }

		const { id: passkeyId, response: passkeyResponse } = passkey;

		if (!passkeyId || !passkeyResponse || !passkeyResponse.userHandle) {
			throw generateError('Unauthorized', 'Invalid passkey', 401);
		}

		try {
			const user = await userService.verifyPasskey(
				passkeyId,
				passkeyResponse.userHandle,
				{
					agent: agent,
					referer: referer,
					ip: ip
				}
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

const verifyOTP = async function ({ authorization }, { totpToken, extendSession }, { agent, referer, ip }) {
	try {
		const { email, uuid, step } = await verifyToken(authorization);

		// The step should be request_otp, otherwise reject
		if (!uuid || !email || step !== 'request_otp') {
			throw generateError('Unauthorized', 'Invalid session.', 401);
		}

		try {
			const user = await userService.verifyOTP(
				{ email, uuid },
				extendSession,
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

const register = async function({ email, password }) {
	try {
		const user = await userService.register(email, password);
	
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
		const { email, uuid, isAuthorized } = await verifyToken(authorization);

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
		const { email, uuid, isAuthorized } = await verifyToken(authorization);

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

exports.login = login;
exports.verifyPassword = verifyPassword;
exports.requestLoginWithPasskey = requestLoginWithPasskey;
exports.verifyPasskey = verifyPasskey;
exports.verifyOTP = verifyOTP;
exports.register = register;
exports.update = update;
exports.getInformation = getInformation;
