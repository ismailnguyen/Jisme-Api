'use strict';

const repository = require('../repository/accountRepository.js');
const { 
    encrypt,
    decrypt
 } = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');

const encryptedFields = [
    'user_id',
    'label',
	'platform',
    'icon',
	'login',
	'password',
	'password_clue',
	'tags',
	'social_login',
	'description',
	'notes',
    'card_number',
    'card_name',
    'card_expiracy',
    'card_issue_date',
    'card_cryptogram',
    'card_pin',
    'totp_secret'
];

const findOne = async function({ accountId, user_id }) {
    if (!user_id) {
		throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const account = await repository.findOne({
            query: {
                _id: accountId,
                user_id: encrypt(user_id)
            }
        });

        if (!account) {
			throw generateError('Error', 'No account found', 404);
		}

        if (account.isServerEncrypted) {
            encryptedFields
                .filter(field => account[field])
                .forEach(field => account[field] = decrypt(account[field]));
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
        const encryptedAccounts = await repository.findAll({
            query: {
                user_id: encrypt(user_id)
            },
            max: 10,
            sortBy: {
                last_opened_date: -1
            }
        });

        if (!encryptedAccounts) {
			throw generateError('Error', 'No accounts found (accountService.findRecents)', 404);
		}

        return encryptedAccounts.reduce((validAccounts, account, index) => {
            try {
                if (account.isServerEncrypted) {
                    encryptedFields
                        .filter(field => account[field])
                        .forEach(field => account[field] = decrypt(account[field]));
                }
                validAccounts.push(account);
            } catch (err) {
                console.error(`Error processing account at index ${index}:`, err);
            }
            return validAccounts;
        }, []);
    }
    catch (error) {
        throw generateError('Error while retrieving accounts (accountService.findRecents)', error.reason, error.code || 404);
    }
}

const count = async function({ user_id }) {
    if (!user_id) {
        throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        return await repository.count({
            query: {
                user_id: encrypt(user_id)
            }
        });
    }
    catch (error) {
        throw generateError('No accounts found (accountService.count)', error.message, error.code || 404);
    }
}

const findAll = async function({ user_id, max, offset }) {
    if (!user_id) {
		throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const encryptedAccounts = await repository.findAll({
            query: {
                user_id: encrypt(user_id)
            },
            max: max,
            offset: offset
        });

        if (!encryptedAccounts) {
			throw generateError('Error', 'No accounts found (accountService.findAll)', 404);
		}

        return encryptedAccounts.reduce((validAccounts, account, index) => {
            try {
                if (account.isServerEncrypted) {
                    encryptedFields
                        .filter(field => account[field])
                        .forEach(field => {
                            try {
                                account[field] = decrypt(account[field]);
                            }
                            catch (decryptionError) {
                                console.error(`Error decrypting field ${field} for account with id ${account._id}}:`, decryptionError);
                            }
                        });
                }
                validAccounts.push(account);
            } catch (err) {
                console.error(`Error decrypting account id ${account._id}:`, err);
            }
            return validAccounts;
        }, []);
    }
    catch (error) {
        throw generateError('Error while retrieving accounts (accountService.findAll)', error.message, 404);
    }
}

const create = async function({ accountToCreate, user_id }) {
    if (!accountToCreate || !user_id) {
		throw generateError('Invalid user input', 'Must provide an account.', 400);
    }

    accountToCreate.user_id = user_id; // this will be encrypted on following lines
    accountToCreate.created_date = accountToCreate.created_date || new Date().toISOString(); // Override with server date if not provided
    accountToCreate.isServerEncrypted = true;

    // enforce server encryption for every account
    encryptedFields
        .filter(field => accountToCreate[field])
        .forEach(field => accountToCreate[field] = encrypt(accountToCreate[field]));

    try {
        const createdAccount = await repository.insertOne(accountToCreate);

        if (createdAccount.isServerEncrypted) {
            encryptedFields
                .filter(field => createdAccount[field])
                .forEach(field => createdAccount[field] = decrypt(createdAccount[field]));
        }

        return createdAccount;
    }
    catch (error) {
        throw generateError('Failed to create new account.', error.message, error.code || 403);
    }
}

const update = async function({ accountIdToUpdate, accountNewValue, user_id }) {
    if (!accountIdToUpdate || !accountNewValue || !user_id) {
		throw generateError('Invalid user input', 'Must provide an account.', 400);
    }
    
    accountNewValue.isServerEncrypted = true;

    // enforce server encryption for every account
    encryptedFields
        .filter(field => accountNewValue[field])
        .forEach(field => accountNewValue[field] = encrypt(accountNewValue[field]));

    try {
        const updatedAccount = await repository.updateOne({
            query: {
                _id: accountIdToUpdate,
                user_id: encrypt(user_id)
            },
            newValue: accountNewValue
        });

        if (updatedAccount.isServerEncrypted) {
            encryptedFields
                .filter(field => updatedAccount[field])
                .forEach(field => updatedAccount[field] = decrypt(updatedAccount[field]));
        }

        return updatedAccount; 
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
                user_id: encrypt(user_id)
            }
        });
    }
    catch (error) {
        throw generateError('Failed to create new user.', error.message, error.code || 403);
    }
}

const enableServerEncryption = async function({ user_id, accounts }) {
    if (!user_id) {
        throw generateError('Invalid user', 'Must provide an user uuid.', 400);
    }

    try {
        const encryptedAccounts = accounts.map(account => {
            account.user_id = user_id; // this will be encrypted on following lines
            account.isServerEncrypted = true;

            encryptedFields
                .filter(field => account[field])
                .forEach(field => account[field] = encrypt(account[field]));

            return account;
        });

        for (let account of encryptedAccounts) {
            if (!account._id) {
                throw generateError('Invalid account', 'Must provide an account id.', 400);
            }

            await repository.updateOne({
                query: {
                    _id: account._id,
                    user_id: account.user_id
                },
                newValue: account
            });
        }

        const decryptedAccounts = encryptedAccounts.map(account => {
            encryptedFields
                .filter(field => account[field])
                .forEach(field => account[field] = decrypt(account[field]));

            return account;
        });

        return decryptedAccounts;
    }
    catch (error) {
        throw generateError('Failed to enable server encryption.', error.message, error.code || 403);
    }
}

exports.count = count;
exports.findOne = findOne;
exports.findRecents = findRecents;
exports.findAll = findAll;
exports.create = create;
exports.update = update;
exports.remove = remove;
exports.enableServerEncryption = enableServerEncryption;
