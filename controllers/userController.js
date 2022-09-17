
const userService = require('../services/userService.js');
const { verifyToken } = require('../helpers/credentialHelper.js');
const { throwError } = require('../helpers/errorHandler.js');

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
		const { email, uuid } = await verifyToken(authorization);

		try {
			const updatedUser = await userService.update(
				{
					email: email,
					uuid: uuid,
				},
				{
					password: payload.password,
					last_update_date: new Date(), // Update last update date at each update
					avatarUrl: payload.avatarUrl
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
		const { email, uuid } = await verifyToken(authorization);

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
exports.register = register;
exports.update = update;
exports.lastUpdateDate = lastUpdateDate;
