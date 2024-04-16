'use strict';

const userService = require('../services/userService.js');
const {
	verifyToken,
	verifyPasskeyChallenge
} = require('../utils/credentials.js');
const { throwError } = require('../utils/errors.js');

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

const loginWithPasskey = async function ({ id, response: { userHandle }}, challenge) {
	try {
		const { agent, referer, ip } = verifyPasskeyChallenge (challenge);

		try {
			const user = await userService.loginWithPasskey(id, userHandle, challenge);
		
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
