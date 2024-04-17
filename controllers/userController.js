'use strict';

const userService = require('../services/userService.js');
const {
	verifyToken,
	verifyPasskeyChallenge
} = require('../utils/credentials.js');
const { throwError, generateError } = require('../utils/errors.js');

const login = async function({ email, password }) {
	try {
		const user = await userService.login(email, password);
	
		return {
			status: 200,
			data: user
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const requestLoginWithPasskey = async function ({ agent, referer, ip}) {
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

const loginWithPasskey = async function ({ passkey, challenge }, client) {
	try {
		if (!passkey || !challenge) {
			throw generateError('Unauthorized', 'Missing passkey/challenge', 401);
		}

		//const { agent, referer, ip } = await verifyPasskeyChallenge (challenge);

		// If the one who request the challenge is not the same as the one who is trying to log, reject the request
		// if (client.agent !== agent || client.referer !== referer || client.ip !== ip) {
		// 	throw generateError('Unauthorized', 'Invalid passkey challenge', 401);
		// }

		const { id: passkeyId, response: passkeyResponse } = passkey;

		if (!passkeyId || !passkeyResponse || !passkeyResponse.userHandle) {
			throw generateError('Unauthorized', 'Invalid passkey', 401);
		}

		try {
			const user = await userService.loginWithPasskey(passkeyId, passkeyResponse.userHandle, challenge);
		
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

const verifyMFA = async function ({ authorization }, { totpToken, extendSession }) {
	try {
		const { email, uuid } = await verifyToken(authorization);

		try {
			const user = await userService.verifyMFA({ email, uuid }, extendSession, totpToken);
		
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
		const { email, uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
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
		const { email, uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
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
exports.requestLoginWithPasskey = requestLoginWithPasskey;
exports.loginWithPasskey = loginWithPasskey;
exports.verifyMFA = verifyMFA;
exports.register = register;
exports.update = update;
exports.getInformation = getInformation;
