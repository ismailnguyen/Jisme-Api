const { 
    generateUnsignedAccessToken,
    generateSignedAccessToken,
    isTotpValid,
    generateTotpSecret
} = require('../helpers/credentialHelper.js');
const {
    findOne,
    updateOne,
    insertOne
} = require('../repository/userRepository.js');
const sha256 = require('sha256');
const { generateError } = require('../helpers/errorHandler.js');

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
            created_date: new Date().toISOString(),
            password: sha256(password), // Encrypt user password with SHA256 algorithm
            uuid: sha256(email + password), // Generate unique id for user
            access_token: generateUnsignedAccessToken(userToRegister), // Generate temporary unique token for user
            totp_secret: generateTotpSecret() // Generate TOTP secret for MFA
        };

        try {
            const registeredUser = await insertOne(userToRegister);

            return {
                _id: registeredUser._id,
                uuid: registeredUser.uuid,
                email: registeredUser.email,
                created_date: registeredUser.created_date,
                last_update_date: registeredUser.last_update_date,
                avatarUrl: registeredUser.avatarUrl,
                token: registeredUser.token,
                totp_secret: registeredUser.totp_secret // This secret is only sent during registration to inform user
            };
        }
        catch (error) {
            throw generateError('Failed to create new user.', error.message, 403);
        }
    }
    catch (error) {
        throw generateError('User not found', error.message, 404);
    }
}

const login = async function(email, password, isExtendedSession) {
    if (!email || !password) {
		throw generateError('Invalid user input', 'Must provide an email and password.', 400);
    }

    let encryptedPassword = sha256(password);

    try {
        const foundUser = await findOne({
            query: { 
                email: email,
                password: encryptedPassword
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        return {
            email: foundUser.email,
            token: generateUnsignedAccessToken(foundUser, isExtendedSession),
            avatarUrl: foundUser.avatarUrl,
            isMFARequired: foundUser.isMFAEnabled
        };
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
                uuid: uuid,
                email: email
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        let user = foundUser;
        
        if (!isTotpValid(totpToken, user.totp_secret)) {
		    throw generateError('Invalid user input', 'Invalid TOTP token.', 401);
        }

        // Generate access token
        user.token = generateSignedAccessToken(user, isExtendedSession);

        // Save new token on database
        return await update({ email: user.email, uuid: user.uuid }, user);
    }
    catch (error) {
        throw generateError(error.name || 'User not found', error.message, error.code || 404);
    }
}

const update = async function({ email, uuid }, payload) {
    try {
        const foundUser = await findOne({
            query: {
                email: email,
                uuid: uuid
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
            email: payload.email || email,
            uuid: payload.uuid || uuid,
            password: payload.password || foundUser.password,
            created_date: foundUser.created_date,
            token: payload.token || foundUser.token,
            // Update with new Date() only it's called directly from the controller
            last_update_date: payload.last_update_date || foundUser.last_update_date,
            avatarUrl: payload.avatarUrl || foundUser.avatarUrl
        };
        
        try {
            const updatedUser = await updateOne({
                query: {
                    email: email,
                    uuid: uuid
                },
                newValue: userToUpdate
            });
    
            return {
                email: updatedUser.email,
                uuid: updatedUser.uuid,
                created_date: updatedUser.created_date,
                token: updatedUser.token,
                last_update_date: updatedUser.last_update_date,
                avatarUrl: updatedUser.avatarUrl,
                isMFAEnabled: updatedUser.isMFAEnabled
            };
        }
        catch (error) {
            throw generateError('Error', 'Failed to update user', 410);
        }
    }
    catch(error) {
        throw generateError('User not found', error.message, 404);
    }
}

const lastUpdateDate = async function({ email, uuid }) {
    if (!email || !uuid) {
		throw generateError('Invalid user', 'Must provide an email and uuid.', 400);
    }

    try {
        const foundUser = await findOne({
            query: {
                email: email,
                uuid: uuid
            }
        });

        if (!foundUser) {
			throw generateError('Error', 'User not found', 404);
		}

        return {
            last_update_date: foundUser.last_update_date
        };
    }
    catch (error) {
        throw generateError('User not found', error.message, 404);
    }
}

exports.register = register;
exports.login = login;
exports.verifyMFA = verifyMFA;
exports.update = update;
exports.lastUpdateDate = lastUpdateDate;
