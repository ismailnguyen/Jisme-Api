'use strict';

const service = require('../services/accountService.js');
const userService = require('../services/userService.js');
const { verifyToken } = require('../utils/credentials.js');
const { throwError, generateError } = require('../utils/errors.js');

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

const findAll = async function({ authorization }, { limit, page }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		const pageNumber = parseInt(page) || 0;
		const limitPerPage = parseInt(limit) || 50;
		const result = {};

		let startIndex = pageNumber * limitPerPage;
    	const endIndex = (pageNumber + 1) * limitPerPage;

		try {
			result.totalAccounts = await service.count({
				user_id: uuid
			});
		}
		catch(error) {
			return throwError(error);
		}

		if (startIndex > 0) {
			result.previous = {
				pageNumber: pageNumber - 1,
				limit: limitPerPage
			};
		}

		if (endIndex < result.totalAccounts) {
			result.next = {
				pageNumber: pageNumber + 1,
				limit: limitPerPage
			};
		}

		result.data = await service.findAll({
			user_id: uuid,
			max: limitPerPage,
			offset: startIndex
		});

		// If the number of accounts is less than the limit per page, set the rowsPerPage to the total number of accounts
		if (limitPerPage > result.totalAccounts) {
			result.rowsPerPage = result.totalAccounts;
		}
		// If the number of accounts is less than the limit per page, set the rowsPerPage to the number of accounts
		else if (result.data.length < limitPerPage) {
			result.rowsPerPage = result.data.length;
		}
		// Otherwise, set the rowsPerPage to the limit per page
		else {
			result.rowsPerPage = limitPerPage;
		}

		return {
			status: 200,
			data: result
		};
	}
	catch (error) {
		return throwError(error);
	}
}

const create = async function({ authorization }, accountToCreate) {
	try {
		const { uuid, email, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const createdAccount = await service.create({
				accountToCreate: accountToCreate,
				user_id: uuid
			});

			// Each time the user makes a change to their account
			// we update the last updated date
			await userService.updateLastUpdatedDate({ email, uuid });

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
		const { uuid, email, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const updatedAccount = await service.update({
				accountIdToUpdate: account_id,
				accountNewValue: accountNewValue,
				user_id: uuid
			});

			// Each time the user makes a change to their account
			// we update the last updated date
			await userService.updateLastUpdatedDate({ email, uuid });

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
		const { uuid, email, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			await service.remove({
				accountIdToRemove: account_id,
				user_id: uuid
			});

			// Each time the user makes a change to their account
			// we update the last updated date
			await userService.updateLastUpdatedDate({ email, uuid });

			return {
				status: 204,
				data: {
					_id: account_id
				}
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

const enableServerEncryption = async function({ authorization }, { accounts }) {
	try {
		const { uuid, mfaValid } = await verifyToken(authorization);

		if (!mfaValid) {
			throw generateError('Unauthorized', 'MFA not valid', 401);
		}

		try {
			const result = await service.enableServerEncryption({
				user_id: uuid,
				accounts: accounts
			});

			return {
				status: 200,
				data: result
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

exports.find = find;
exports.findRecents = findRecents;
exports.findAll = findAll;
exports.create = create;
exports.update = update;
exports.remove = remove;
exports.enableServerEncryption = enableServerEncryption;
