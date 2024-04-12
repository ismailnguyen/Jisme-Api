'use strict';

const { decrypt } = require('dotenv');
const repository = require('../repository/accountRepository.js');
const { generateError } = require('../utils/errors.js');

const findOne = async function({ accountId, user_id }) {
    if (!user_id) {
		throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const account = await repository.findOne({
            query: {
                _id: accountId,
                user_id: user_id
            }
        });

        if (!account) {
			throw generateError('Error', 'No account found', 404);
		}

        if (account.isServerEncrypted) {
            decrypt(account, PRIVATE_);
        }

        return account;
    }
    catch (error) {
        throw generateError('No account found', error.message, error.code || 404);
    }
}

const findRecents = async function({ user_id }) {
    if (!user_id) {
		throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const accounts = await repository.findAll({
            query: {
                user_id: user_id
            },
            max: 10,
            sortBy: {
                last_opened_date: -1
            }
        });

        if (!accounts) {
			throw generateError('Error', 'No accounts found', 404);
		}

        return accounts;
    }
    catch (error) {
        throw generateError('No accounts found', error.reason, error.code || 404);
    }
}

const count = async function({ user_id }) {
    if (!user_id) {
        throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        return await repository.count({
            query: {
                user_id: user_id
            }
        });
    }
    catch (error) {
        throw generateError('No accounts found', error.message, error.code || 404);
    }
}

const findAll = async function({ user_id, max, offset }) {
    if (!user_id) {
		throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const accounts = await repository.findAll({
            query: {
                user_id: user_id
            },
            max: max,
            offset: offset
        });

        if (!accounts) {
			throw generateError('Error', 'No accounts found', 404);
		}

        return accounts;
    }
    catch (error) {
        throw generateError('No accounts found', error.message, 404);
    }
}

const create = async function({ accountToCreate, user_id }) {
    if (!accountToCreate || !user_id) {
		throw generateError('Invalid user input', 'Must provide an account.', 400);
    }

    accountToCreate.user_id = user_id;
    accountToCreate.created_date = new Date().toISOString();

    try {
        return await repository.insertOne(accountToCreate);
    }
    catch (error) {
        throw generateError('Failed to create new account.', error.message, error.code || 403);
    }
}

const update = async function({ accountIdToUpdate, accountNewValue, user_id }) {
    if (!accountIdToUpdate || !accountNewValue || !user_id) {
		throw generateError('Invalid user input', 'Must provide an account.', 400);
    }

    try {
        return await repository.updateOne({
            query: {
                _id: accountIdToUpdate,
                user_id: user_id
            },
            newValue: accountNewValue
        });
    }
    catch (error) {
        throw generateError('Failed to update account.', error.message, error.code || 403);
    }
}

const remove = async function({ accountIdToRemove, user_id }) {
    if (!accountIdToRemove || !user_id) {
		throw generateError('Invalid user input', 'Must provide an account.', 400);
    }

    try {
        return await repository.deleteOne({
            query: {
                _id: accountIdToRemove,
                user_id: user_id
            }
        });
    }
    catch (error) {
        throw generateError('Failed to create new user.', error.message, error.code || 403);
    }
}

exports.count = count;
exports.findOne = findOne;
exports.findRecents = findRecents;
exports.findAll = findAll;
exports.create = create;
exports.update = update;
exports.remove = remove;
