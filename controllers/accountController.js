const service = require('../services/accountService.js');
const { verifyToken } = require('../helpers/credentialHelper.js');
const { throwError, generateError } = require('../helpers/errorHandler.js');

const find = async function({ authorization }, { account_id }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const account = await service.findOne({
				accountId: account_id,
				user_id: uuid
			});

			return {
				status: 200,
				data: account
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

const findRecents  = async function({ authorization }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const accounts = await service.findRecents({
				user_id: uuid
			});

			return {
				status: 200,
				data: accounts
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

const findAll = async function({ authorization }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const accounts = await service.findAll({
				user_id: uuid
			});

			return {
				status: 200,
				data: accounts
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

const create = async function({ authorization }, accountToCreate) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const createdAccount = await service.create({
				accountToCreate: accountToCreate,
				user_id: uuid
			});

			return {
				status: 201,
				data: createdAccount
			};
		} catch(error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

const update = async function({ authorization }, { account_id }, accountNewValue) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const updatedAccount = await service.update({
				accountIdToUpdate: account_id,
				accountNewValue: accountNewValue,
				user_id: uuid
			});

			return {
				status: 201,
				data: updatedAccount
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

const remove = async function({ authorization }, { account_id }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			await service.remove({
				accountIdToRemove: account_id,
				user_id: uuid
			});

			response.status(204).json({
				_id: account_id
			});
		}
		catch(error) {
			return throwError(error);
		}
	}
	catch (error) {
		return throwError(error);
	}
}

exports.find = find;
exports.findRecents = findRecents;
exports.findAll = findAll;
exports.create = create;
exports.update = update;
exports.remove = remove;
