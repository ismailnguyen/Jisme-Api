'use strict';
const {
    login_delay_in_seconds
 } = require('../utils/config.js');

const { 
    findLocationFromIp
} = require('../utils/location.js');

const { 
    generatePublicKey,
    generateUnsignedAccessToken,
    generateSignedAccessToken,
    getTokenExpiration,
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
const accountService = require('../services/accountService.js');

// Response-only projection: never write merged credentials into users.passkeys.
const responsePasskeys = async (user) => {
    const credentials = require('../repository/webauthnCredentialRepository.js');
    const verified = await credentials.listByUser(decrypt(user.uuid));
    const seen = new Set();
    const result = [];
    const append = (entry, id, isVerified) => {
        if (typeof id !== 'string' || !id || seen.has(id)) return;
        seen.add(id);
        const item = { id, verified: isVerified };
        const name = entry.name ?? entry.deviceName;
        if (name !== undefined) item.name = name;
        if (entry.createdAt !== undefined) item.createdAt = entry.createdAt;
        if (entry.transports !== undefined) item.transports = entry.transports;
        result.push(item);
    };
    for (const entry of verified) append(entry, entry.credentialId, true);
    for (const entry of Array.isArray(user.passkeys) ? user.passkeys : []) {
        if (entry && typeof entry === 'object') {
            append(entry, entry.id ?? entry.credentialId ?? entry.passkey?.id, false);
        }
    }
    return result;
};

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
                public_encryption_key: registeredUser.public_encryption_key,
                hasAccounts: false,
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

const requestOTPVerification = ({ email, uuid, avatarUrl, isOtpRequired, hasPasskey, passkeys, client }) => {
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
        passkeys,
        next: {
            step: 'verify_otp',
            url: '/login/otp'
        }
    };
}

const requestPasswordVerification = ({ email, uuid, isOtpRequired, hasPasskey, passkeys, client }) => {
    return {
        email: decrypt(email),
        token: generateUnsignedAccessToken({
            email: decrypt(email),
            uuid: decrypt(uuid),
            step: 'request_password'
        }, client),
        isPasswordRequired: !hasPasskey, // if there is no passkey, and MFA is enabled, requires pwd
        isOtpRequired: isOtpRequired,
        hasPasskey: hasPasskey,
        passkeys,
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

        // Only credentials from verified enrollment count. Legacy, never-verified
        // passkeys (users.passkeys) do not set this flag and must re-enroll.
        const hasPasskey = foundUser.hasVerifiedPasskey === true;
        const hasMFA = foundUser.isMFAEnabled;

        // Otherwise request password login
        return requestPasswordVerification({
            email: foundUser.email,
            uuid: foundUser.uuid,
            isOtpRequired: hasMFA,
            hasPasskey: hasPasskey,
            passkeys: await responsePasskeys(foundUser),
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
        // Only credentials from verified enrollment count. Legacy, never-verified
        // passkeys (users.passkeys) do not set this flag and must re-enroll.
        const hasPasskey = foundUser.hasVerifiedPasskey === true;

        // If user has MFA, request MFA login
        if (hasMFA) {
            return requestOTPVerification({
                email: foundUser.email,
                uuid: foundUser.uuid,
                avatarUrl: foundUser.avatarUrl,
                isOtpRequired: hasMFA,
                hasPasskey: hasPasskey,
                passkeys: await responsePasskeys(foundUser),
                client: { agent, referer, ip }
            });
        }

        return await login(
            {
                email: decrypt(foundUser.email),
                uuid: decrypt(foundUser.uuid),
                isExtendedSession: isExtendedSession,
                amr: ['pwd']
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
                isExtendedSession: isExtendedSession,
                // Reached only through the password step (request_otp token).
                amr: ['pwd', 'otp']
            },
            { agent, referer, ip }
        );
    }
    catch (error) {
        throw generateError(error.name || error.message || 'Error', error.reason, error.code || 404);
    }
}

// Passkey login: { challenge, response } from an authentication ceremony whose
// options came from POST users/login/passkey/options (challenge bound to this
// uuid). Verified cryptographically against credentials from verified
// enrollment only. Anything else, notably legacy identifier-only payloads and
// legacy never-verified passkeys, gets the re-enrollment 403.
const verifyPasskey = async function(session, payload, client) {
    if (!session || typeof session !== 'object' || typeof session.uuid !== 'string' || !session.uuid
        || !payload || typeof payload !== 'object' || typeof payload.challenge !== 'string'
        || !payload.response || typeof payload.response !== 'object') {
        throw generateError('Passkey re-enrollment required',
            'Sign in with password (and MFA if enabled), then re-enroll your passkey via verified enrollment.', 403);
    }
    // Lazy: keeps this module loadable in isolation for the legacy tests.
    const passkeyService = require('./passkeyService.js');
    const { enforceRateLimit } = require('./sessionPolicy.js');
    enforceRateLimit(session.uuid, 'login');
    await passkeyService.authenticate(session.uuid, payload, 'authentication', client);

    const foundUser = await findUser({ query: { uuid: encrypt(session.uuid) } });
    if (!foundUser) {
        throw generateError('Unauthorized', 'User not found', 401);
    }
    return await login(
        {
            email: decrypt(foundUser.email),
            uuid: session.uuid,
            isExtendedSession: payload.isExtendedSession === true,
            amr: ['webauthn']
        },
        client || {}
    );
}

const login = async function({ email, uuid, isExtendedSession = false, amr = [] }, { agent, referer, ip}) {
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

        let locationString = '';
        // If 'ip' contains multiple IPs, take the first one
        let ipToUse = ip && ip.indexOf(',') > -1 ? ip.split(',')[0].trim() : ip;
        const location = await findLocationFromIp(ipToUse);
        if (location && (location.city || location.country_name)) {
            locationString = `${ location.city ? location.city + ', ' : '' }${ location.country_name }`;
        }

        // Log clients informations into acvitiy logs
        await logActivity({
            uuid: encrypt(uuid),
            action: encrypt('login'),
            agent: encrypt(agent),
            referer: encrypt(referer),
            ip: encrypt(ip),
            activity_date: new Date().toISOString(),
            location: encrypt(locationString)
        });

        const hasAccounts = await accountService.count({ user_id: uuid }) > 0;

        const token = generateSignedAccessToken(
            {
                email: email,
                uuid: uuid
            },
            isExtendedSession,
            { agent, referer, ip },
            { amr }
        );

        // Save new token on database
        return await update({ email: email, uuid: uuid }, {
            token: token,
            tokenExpiry: getTokenExpiration(token),
            hasAccounts: hasAccounts,
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
    payload = payload || {};
    if (payload.passkeys !== undefined) {
        // Raw client-supplied passkeys are never accepted. The only write path is
        // verified enrollment (POST users/passkeys/options + POST users/passkeys).
        throw generateError('Passkey re-enrollment required', 'Use verified enrollment; client-supplied passkeys are not accepted.', 403);
    }
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
            token: payload.token ? encrypt(payload.token) : foundUser.token,
            hasAccounts: !!payload.hasAccounts || !!foundUser.hasAccounts,
        };
        
        try {
            const decryptedToken = decrypt(userToUpdate.token);
            const resolvedTokenExpiry = payload.tokenExpiry != null
                ? payload.tokenExpiry
                : getTokenExpiration(decryptedToken);

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
                token: decryptedToken,
                tokenExpiry: resolvedTokenExpiry,
                avatarUrl: decrypt(userToUpdate.avatarUrl),
                isMFAEnabled: userToUpdate.isMFAEnabled,
                passkeys: await responsePasskeys(foundUser),
                hasAccounts: userToUpdate.hasAccounts,

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

        const hasAccounts = await accountService.count({ user_id: uuid }) > 0;

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
            passkeys: await responsePasskeys(foundUser),
            activities: activities.map(a => ({
                action: decrypt(a.action),
                agent: decrypt(a.agent),
                referer: decrypt(a.referer),
                ip: decrypt(a.ip),
                activity_date: a.activity_date,
                location: decrypt(a.location)
            })),
            hasAccounts: hasAccounts
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
