'use strict';
const {
    login_delay_in_seconds
 } = require('../utils/config.js');

const { 
    generatePublicKey,
    generateUnsignedAccessToken,
    generateSignedAccessToken,
    isTotpValid,
    generateTotpSecret,
    generatePasskeyChallenge
} = require('../utils/credentials.js');
const {
    findOne,
    updateOne,
    insertOne
} = require('../repository/userRepository.js');
const {
    hash,
    encrypt,
    decrypt
} = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');

const register = async function(email, password) {
    if (!email || !password) {
		throw generateError('Invalid user input', 'Must provide an email and password.', 400);
    }

    // Check first if user already exists
    try {
        const existingUser = await findOne({
            query: { email: email }
        });

        if (existingUser) {
			throw generateError('Error', 'User already exists', 403);
		}

        let userToRegister = {
            uuid: hash(email + password), // Generate unique id for user
            email: email,
            created_date: new Date().toISOString(),
            last_update_date: new Date().toISOString(),
            password: hash(password), // Hash user password with SHA256 algorithm
            token: generateUnsignedAccessToken(userToRegister), // Generate temporary unique token for user
            totp_secret: generateTotpSecret(), // Generate TOTP secret for MFA
            public_encryption_key: generatePublicKey(email, password), // Generate public encryption key for user
        };

        try {
            const registeredUser = await insertOne(userToRegister);

            return {
                _id: registeredUser._id,
                uuid: registeredUser.uuid,
                email: registeredUser.email,
                created_date: registeredUser.created_date,
                last_update_date: registeredUser.last_update_date,
                // avatarUrl: registeredUser.avatarUrl, // This is not set during registration
                token: registeredUser.token,
                totp_secret: registeredUser.totp_secret, // This secret is only sent during registration to inform user
                public_encryption_key: registeredUser.public_encryption_key
            };
        }
        catch (error) {
            throw generateError('Failed to create new user.', error.message, error.code || 403);
        }
    }
    catch (error) {
        throw generateError('User not found', error.message, 404);
    }
}

const login = async function(email, password) {
    if (!email || !password) {
		throw generateError('Invalid user input', 'Must provide an email and password.', 400);
    }

    let hashedPassword = hash(password);

    try {
        const foundUser = await findOne({
            query: { 
                email: encrypt(email),
                password: encrypt(hashedPassword)
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        // Verify last login action
		// if the user logged in less than X minutes ago (configured by env variables),
		// don't allow him to log in again, and ask to wait 5 minutes before retrying
        // This extra check do not apply for passkey login because there is no brute force attack possible
		const lastLogin = new Date(foundUser.last_login_date);

        // 300 seconds is default value when config is missing
        const loginDelay = (login_delay_in_seconds || 300) * 1000; // 5 minutes in milliseconds
        if (lastLogin && (new Date() - lastLogin) < loginDelay) {
            throw generateError('Unauthorized', 'Too many login attempt. Please retry later.', 401);
        }

        return {
            email: decrypt(foundUser.email),
            token: generateUnsignedAccessToken({
                email: decrypt(foundUser.email),
                uuid: decrypt(foundUser.uuid)
            }),
            avatarUrl: decrypt(foundUser.avatarUrl),
            isMFARequired: foundUser.isMFAEnabled
        };
    }
    catch (error) {
        throw generateError(error.reason ? error.message : 'User not found', error.reason || error.message, error.code || 404);
    }
}

const requestLoginWithPasskey = async function({ agent, referer, ip}) {
    try {
        return {
            challenge: generatePasskeyChallenge({ 
                agent: agent, 
                referer: referer, 
                ip: ip
            })
        };
    }
    catch (error) {
        throw generateError('User not found', error.message, 404);
    }
}

const loginWithPasskey = async function(passkeyId, userId, challenge) {
    if (!passkeyId || !userId) {
		throw generateError('Invalid user input', 'Must provide a passkey.', 400);
    }

    try {
        const foundUser = await findOne({
            query: { 
                uuid: encrypt(userId)
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        const isPasskeyMatching = foundUser.passkeys.find(p => p.passkey.id === passkeyId);

        if (!isPasskeyMatching) {
			throw generateError('Error', 'Invalid passkey', 401);
        }

        const decryptedEmail = decrypt(foundUser.email);
        const decryptedUuid = decrypt(foundUser.uuid);

        // Save new token on database
        return await update({ email: decryptedEmail, uuid: decryptedUuid }, {
            // Generate access token
            token: generateSignedAccessToken({
                email: decryptedEmail,
                uuid: decryptedUuid
            }, false),
            last_login_date: new Date().toISOString()
        });
    }
    catch (error) {
        throw generateError('User not found', error.message, 404);
    }
}

const verifyMFA = async function({ email, uuid }, isExtendedSession, totpToken) {
    if (!totpToken) {
		throw generateError('Invalid user input', 'Must provide a TOTP token.', 400);
    }

    try {
        const foundUser = await findOne({
            query: { 
                uuid: encrypt(uuid),
                email: encrypt(email)
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        let user = foundUser;
        
        if (!isTotpValid(totpToken, decrypt(user.totp_secret))) {
		    throw generateError('Invalid user input', 'Invalid TOTP token.', 401);
        }

        const decryptedEmail = decrypt(user.email);
        const decryptedUuid = decrypt(user.uuid);

        // Save new token on database
        return await update({ email: decryptedEmail, uuid: decryptedUuid }, {
            // Generate access token
            token: generateSignedAccessToken({
                email: decryptedEmail,
                uuid: decryptedUuid
            }, isExtendedSession),
            last_login_date: new Date().toISOString()
        });
    }
    catch (error) {
        throw generateError(error.name || error.message || 'User not found', error.reason, error.code || 404);
    }
}

const updateLastUpdatedDate = async function({ email, uuid }) {
    let userToUpdate = {
        last_update_date: new Date().toISOString(),
    };

    update({ email: email, uuid: uuid }, userToUpdate);
}

const update = async function({ email, uuid }, payload) {
    try {
        const encryptedEmail = encrypt(email);
        const encryptedUuid = encrypt(uuid);

        // const decryptedEmail = decrypt(email);
        // const decryptedUuid = decrypt(uuid);

        const foundUser = await findOne({
            query: {
                email: encryptedEmail,
                uuid: encryptedUuid
            }
        });
    
        if (!foundUser) {
            throw generateError('Error', 'User not found', 404);
        }

        //TODO: Allow user to specify a new email in 'payload'
        // But add check to find if that email isn't already used
        // Then throw error if email is already taken
        // Remove forced email, uuid pass in controller

        let userToUpdate = {
            email: encryptedEmail,
            uuid: encryptedUuid,
            password: payload.password ? encrypt(payload.password) : foundUser.password,
            created_date: foundUser.created_date,
            // Update with new Date() only it's called directly from the controller
            last_update_date: payload.last_update_date || foundUser.last_update_date,
            last_login_date: payload.last_login_date || foundUser.last_login_date,
            avatarUrl: payload.avatarUrl ? encrypt(payload.avatarUrl) : foundUser.avatarUrl,
            passkeys: payload.passkeys || foundUser.passkeys,
            token: payload.token ? encrypt(payload.token) : foundUser.token
        };
        
        try {
            await updateOne({
                query: {
                    email: encryptedEmail,
                    uuid: encryptedUuid
                },
                newValue: userToUpdate
            });
    
            // use foundUser or userToUpdate to get the updated user because updateOne doesn't return the updated user
            return {
                email: email,
                uuid: uuid,
                created_date: userToUpdate.created_date,
                last_update_date: userToUpdate.last_update_date,
                last_login_date: userToUpdate.last_login_date,
                token: decrypt(userToUpdate.token),
                avatarUrl: decrypt(userToUpdate.avatarUrl),
                isMFAEnabled: userToUpdate.isMFAEnabled,
                passkeys: userToUpdate.passkeys,

                // as these are not updated, there are only present in the first find request
                totp_secret: decrypt(foundUser.totp_secret), 
                public_encryption_key: decrypt(foundUser.public_encryption_key),
            };
        }
        catch (error) {
            throw generateError('Error', 'Failed to update user', error.code || 410);
        }
    }
    catch(error) {
        throw generateError('User not found', error.message, error.code || 404);
    }
}

const getInformation = async function({ email, uuid }) {
    if (!email || !uuid) {
		throw generateError('Invalid user', 'Must provide an email and uuid.', 400);
    }

    try {
        const foundUser = await findOne({
            query: {
                email: encrypt(email),
                uuid: encrypt(uuid)
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        return {
            email: decrypt(foundUser.email),
            uuid: decrypt(foundUser.uuid),
            created_date: foundUser.created_date,
            token: decrypt(foundUser.token),
            last_update_date: foundUser.last_update_date,
            avatarUrl: decrypt(foundUser.avatarUrl),
            isMFAEnabled: foundUser.isMFAEnabled,
            totp_secret: decrypt(foundUser.totp_secret),
            public_encryption_key: decrypt(foundUser.public_encryption_key),
            passkeys: foundUser.passkeys
        };
    }
    catch (error) {
        throw generateError('User not found', error.message, error.code || 404);
    }
}

exports.register = register;
exports.login = login;
exports.requestLoginWithPasskey = requestLoginWithPasskey;
exports.loginWithPasskey = loginWithPasskey;
exports.verifyMFA = verifyMFA;
exports.updateLastUpdatedDate = updateLastUpdatedDate;
exports.update = update;
exports.getInformation = getInformation;
