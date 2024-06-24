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
    fakeUser
} = require('../utils/credentials.js');
const {
    findOne: findUser,
    updateOne: updateUser,
    insertOne: insertUser
} = require('../repository/userRepository.js');
const {
    findAll: findAllActivities,
    insertOne: logActivity,
    deleteOne: deleteActivity
} = require('../repository/userActivitiesRepository.js');
const {
    hash,
    encrypt,
    decrypt
} = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');

const register = async function({ email, password }, client) {
    if (!email || !password) {
		throw generateError('Invalid user input', 'Must provide an email and password.', 400);
    }

    // Check first if user already exists
    try {
        const existingUser = await findUser({
            query: { email: email }
        });

        if (existingUser) {
			throw generateError('Error', 'User already exists', 403);
		}

        const generatedUuid = hash(email + password); // Generate unique id for user
        const hashedPassword = hash(password); // Hash user password with SHA256 algorithm
        const today = new Date().toISOString();

        let userToRegister = {
            uuid: generatedUuid,
            email: email,
            created_date: today,
            last_update_date: today,
            password: hashedPassword,
            token: generateUnsignedAccessToken({
                email: email,
                uuid: generatedUuid,
                step: 'register'
            }, client), // Generate temporary unique token for user
            totp_secret: generateTotpSecret(), // Generate TOTP secret for MFA
            public_encryption_key: generatePublicKey(email, hashedPassword), // Generate public encryption key for user
        };

        try {
            const registeredUser = await insertUser(userToRegister);

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

const requestPassKeyVerification = ({ email, uuid, isOtpRequired, hasPasskey, client }) => {
    return {
        email: decrypt(email),
        token: generateUnsignedAccessToken({
            email: decrypt(email),
            uuid: decrypt(uuid),
            step: 'request_passkey'
        }, client),
        isPasswordRequired: !hasPasskey, // if there is a passkey, password becomes not mandatory
        isOtpRequired: isOtpRequired,
        hasPasskey: hasPasskey,
        next: {
            step: 'verify_passkey',
            url: '/login/passkey'
        }
    };
}

const requestOTPVerification = ({ email, uuid, avatarUrl, isOtpRequired, hasPasskey, client }) => {
    return {
        email: decrypt(email),
        token: generateUnsignedAccessToken({
            email: decrypt(email),
            uuid: decrypt(uuid),
            step: 'request_otp'
        }, client),
        avatarUrl: decrypt(avatarUrl),
        isPasswordRequired: isOtpRequired && !hasPasskey, // if there is no passkey, and MFA is enabled, requires pwd
        isOtpRequired: isOtpRequired,
        hasPasskey: hasPasskey,
        next: {
            step: 'verify_otp',
            url: '/login/otp'
        }
    };
}

const requestPasswordVerification = ({ email, uuid, isOtpRequired, hasPasskey, client }) => {
    return {
        email: decrypt(email),
        token: generateUnsignedAccessToken({
            email: decrypt(email),
            uuid: decrypt(uuid),
            step: 'request_password'
        }, client),
        isPasswordRequired: isOtpRequired && !hasPasskey, // if there is no passkey, and MFA is enabled, requires pwd
        isOtpRequired: isOtpRequired,
        hasPasskey: hasPasskey,
        next: {
            step: 'verify_password',
            url: '/login/password'
        }
    };
}

const requestLogin = async function(email, { agent, referer, ip}) {
    if (!email) {
		throw generateError('Invalid user input', 'Must provide an email.', 400);
    }

    try {
        const foundUser = await findUser({
            query: { 
                email: encrypt(email)
            }
        });

        // If given user is not found, return a fake user to avoid timing attacks
        if (!foundUser) {
			return fakeUser(email, { agent, referer, ip });
		}

        const hasPasskey = foundUser.passkeys && foundUser.passkeys.length > 0;
        const hasMFA = foundUser.isMFAEnabled;

        // If user has passkey, request passkey login
        if (hasPasskey) {
            return requestPassKeyVerification({
                email: foundUser.email,
                uuid: foundUser.uuid,
                isOtpRequired: hasMFA,
                hasPasskey: hasPasskey,
                client: { agent, referer, ip }
            });
        }

        // Otherwise request password login
        return requestPasswordVerification({
            email: foundUser.email,
            uuid: foundUser.uuid,
            isOtpRequired: hasMFA,
            hasPasskey: hasPasskey,
            client: { agent, referer, ip }
        });
    }
    catch (error) {
        throw generateError(error.reason ? error.message : 'Error', error.reason || error.message, error.code || 404);
    }
}

const verifyPassword = async function(uuid, password, isExtendedSession, { agent, referer, ip }) {
    if (!uuid || !password) {
		throw generateError('Invalid user input', 'Must provide user password.', 400);
    }

    let hashedPassword = hash(password);

    try {
        const foundUser = await findUser({
            query: { 
                uuid: encrypt(uuid),
                password: encrypt(hashedPassword)
            }
        });

        if (!foundUser) {
			throw generateError('Unauthorized', 'User not found', 404);
		}

        // Verify last login action
		// if the user logged in less than X minutes ago (configured by env variables),
		// don't allow him/her to log in again, and ask to wait 5 minutes before retrying
        // This extra check do not apply for passkey login because there is no brute force attack possible
		const lastLogin = new Date(foundUser.last_login_date);

        // 300 seconds is default value when config is missing
        const loginDelay = (login_delay_in_seconds || 300) * 1000; // 5 minutes in milliseconds
        if (lastLogin && (new Date() - lastLogin) < loginDelay) {
            throw generateError('Unauthorized', 'Too many login attempt. Please retry later.', 401);
        }

        const hasMFA = foundUser.isMFAEnabled;
        const hasPasskey = foundUser.passkeys && foundUser.passkeys.length > 0;

        // If user has MFA, request MFA login
        if (hasMFA) {
            return requestOTPVerification({
                email: foundUser.email,
                uuid: foundUser.uuid,
                avatarUrl: foundUser.avatarUrl,
                isOtpRequired: hasMFA,
                hasPasskey: hasPasskey,
                client: { agent, referer, ip }
            });
        }

        return await login(
            {
                email: decrypt(foundUser.email),
                uuid: decrypt(foundUser.uuid),
                isExtendedSession: isExtendedSession
            },
            { agent, referer, ip }
        );
    }
    catch (error) {
        throw generateError(error.reason ? error.message : 'Error', error.reason || error.message, error.code || 404);
    }
}

const verifyOTP = async function({ email, uuid }, isExtendedSession, totpToken, { agent, referer, ip }) {
    if (!totpToken) {
		throw generateError('Invalid user input', 'Must provide a TOTP token.', 400);
    }

    try {
        const foundUser = await findUser({
            query: { 
                uuid: encrypt(uuid),
                email: encrypt(email)
            }
        });

        if (!foundUser) {
			throw generateError('Unauthorized', 'User not found', 404);
		}

        const isTotpValidResult = isTotpValid(totpToken, decrypt(foundUser.totp_secret));
        if (!isTotpValidResult) {
		    throw generateError('Invalid user input', 'Invalid TOTP token.', 401);
        }

        return await login(
            {
                email: decrypt(foundUser.email),
                uuid: decrypt(foundUser.uuid),
                isExtendedSession: isExtendedSession
            },
            { agent, referer, ip }
        );
    }
    catch (error) {
        throw generateError(error.name || error.message || 'Error', error.reason, error.code || 404);
    }
}

const verifyPasskey = async function(passkeyId, userId, isExtendedSession, { agent, referer, ip }) {
    if (!passkeyId || !userId) {
		throw generateError('Invalid user input', 'Must provide a passkey.', 400);
    }

    try {
        const foundUser = await findUser({
            query: { 
                uuid: encrypt(userId)
            }
        });

        if (!foundUser) {
			throw generateError('Unauthorized', 'User not found', 404);
		}

        const isPasskeyMatching = foundUser.passkeys.find(p => p.passkey.id === passkeyId);

        if (!isPasskeyMatching) {
			throw generateError('Unauthorized', 'Invalid passkey', 401);
        }

        return await login(
            {
                email: decrypt(foundUser.email),
                uuid: decrypt(foundUser.uuid),
                isExtendedSession: isExtendedSession
            },
            { agent, referer, ip }
        );
    }
    catch (error) {
        throw generateError(error.message || 'Error', error.reason || error.message, 404);
    }
}

const login = async function({ email, uuid, isExtendedSession = false }, { agent, referer, ip}) {
    try {
        // If there are more than 10 activities, delete the oldest one
        const activities = await findAllActivities({
            query: {
                uuid: encrypt(uuid)
            }
        });

        if (activities && activities.length >= 10) {
            await deleteActivity({
                query: {
                    _id: activities[0]._id
                }
            });
        }

        // Log clients informations into acvitiy logs
        await logActivity({
            uuid: encrypt(uuid),
            action: encrypt('login'),
            agent: encrypt(agent),
            referer: encrypt(referer),
            ip: encrypt(ip),
            activity_date: new Date().toISOString()
        });

        // Save new token on database
        return await update({ email: email, uuid: uuid }, {
            // Generate access token
            token: generateSignedAccessToken(
                {
                    email: email,
                    uuid: uuid
                },
                isExtendedSession,
                { agent, referer, ip }
            ),
            last_login_date: new Date().toISOString()
        });
    }
    catch (error) {
        throw generateError(error.message || 'Error', error.reason || error.message, 404);
    }
}

const updateLastUpdatedDate = async function({ email, uuid }, last_update_date) {
    let userToUpdate = {
        last_update_date: last_update_date || new Date().toISOString(),
    };

    update({ email: email, uuid: uuid }, userToUpdate);
}

const update = async function({ email, uuid }, payload) {
    try {
        const encryptedEmail = encrypt(email);
        const encryptedUuid = encrypt(uuid);

        const foundUser = await findUser({
            query: {
                email: encryptedEmail,
                uuid: encryptedUuid
            }
        });

        if (!foundUser) {
            throw generateError('Unauthorized', 'User not found', 404);
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
            await updateUser({
                query: {
                    email: encryptedEmail,
                    uuid: encryptedUuid
                },
                newValue: userToUpdate
            });
    
            // use foundUser or userToUpdate to get the updated user because updateUser doesn't return the updated user
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
        throw generateError(error.message || 'Error', error.message, error.code || 404);
    }
}

const getInformation = async function({ email, uuid }) {
    if (!email || !uuid) {
		throw generateError('Invalid user', 'Must provide an email and uuid.', 400);
    }

    try {
        const foundUser = await findUser({
            query: {
                email: encrypt(email),
                uuid: encrypt(uuid)
            }
        });

        if (!foundUser) {
			throw generateError('Unauthorized', 'User not found', 404);
		}

        const activities = await findAllActivities({
            query: {
                uuid: encrypt(uuid)
            }
        });

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
            passkeys: foundUser.passkeys,
            activities: activities.map(a => ({
                action: decrypt(a.action),
                agent: decrypt(a.agent),
                referer: decrypt(a.referer),
                ip: decrypt(a.ip),
                activity_date: a.activity_date
            }))
        };
    }
    catch (error) {
        throw generateError(error.message || 'Error', error.message, error.code || 404);
    }
}

exports.register = register;
exports.requestLogin = requestLogin;
exports.login = login;
exports.verifyPassword = verifyPassword;
exports.verifyPasskey = verifyPasskey;
exports.verifyOTP = verifyOTP;
exports.updateLastUpdatedDate = updateLastUpdatedDate;
exports.update = update;
exports.getInformation = getInformation;
