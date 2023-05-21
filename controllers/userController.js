
const userService = require('../services/userService.js');
const { verifyToken } = require('../helpers/credentialHelper.js');
const { throwError } = require('../helpers/errorHandler.js');

const login = async function({ email, password, extendSession }) {
	try {
		const user = await userService.login(email, password, extendSession);
	
		return {
			status: 200,
			data: user
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const loginWithPasskey = async function (passkey) {
	try {
		const user = await userService.loginWithPasskey(passkey);
	
		return {
			status: 200,
			data: user
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const verifyMFA = async function ({ authorization }, { totpToken }) {
	try {
		const { email, uuid, extendedExpiration } = await verifyToken(authorization);

		try {
			const user = await userService.verifyMFA({ email, uuid }, extendedExpiration, totpToken);
		
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
					last_update_date: new Date(), // Update last update date at each update
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

const lastUpdateDate = async function({ authorization }) {
	try {
		const { email, uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const lastUpdateDate = await userService.lastUpdateDate(
				{
					email: email,
					uuid: uuid,
				}
			);

			return {
				status: 200,
				data: lastUpdateDate
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
exports.loginWithPasskey = loginWithPasskey;
exports.verifyMFA = verifyMFA;
exports.register = register;
exports.update = update;
exports.lastUpdateDate = lastUpdateDate;
