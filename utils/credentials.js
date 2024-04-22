'use strict';

const { sign, verify } = require('jsonwebtoken');
const { authenticator } = require('otplib');
const sha256 = require('sha256');
const {
  token_master_secret,
  encryption_public_key_salt,
  passkey_challenge_private_key
} = require('./config.js');
const { generateError } = require('../utils/errors.js');

// Generate a private key for encryption
// This key will be needed to be combined with a protected private key to use encryption
const generatePublicKey = function (email, password) {
  return sha256(email + password + encryption_public_key_salt + Math.random());
}

const generateTotpSecret = function () {
  return authenticator.generateSecret();
}

const isTotpValid = function (totpToken, totpSecret) {
  try {
    return authenticator.check(totpToken, totpSecret);
  } catch (error) {
    throw generateError('TOTP verification failed', error, 401);
  }
}

// TODO: refactor passkey challenge verification with this
// include client details to enforce security always
// change mfaValid by isAuthorized
const generateAccessToken = function ({ email, uuid, extendedExpiration, step, isAuthorized }) {
  return sign({
      email: email,
      uuid: uuid,
      step: step,
      isAuthorized: isAuthorized,
    },
    token_master_secret,
    { 
      expiresIn: extendedExpiration ? '90 days' : '72h'
    }
  );
}

const generateUnsignedAccessToken = function ({ email, uuid, step }) {
  return generateAccessToken({
    email: email,
    uuid: uuid,
    step: step,
    isAuthorized: false,
    extendedExpiration: false
  });
}

const generateSignedAccessToken = function ({ email, uuid}, extendedExpiration) {
  return generateAccessToken({
    email: email,
    uuid: uuid,
    step: 'loggedIn',
    isAuthorized: true,
    extendedExpiration: extendedExpiration
  });
}

const verifyToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1]; // Remove Bearer

  if (!accessToken) {
		throw generateError('Error while verifying token (credentials.verifyToken)', 'Access Token not found (credentials.verifyToken)', 401);
  }

  try {
    const { email, uuid, step, isAuthorized } = await verify(accessToken, token_master_secret);
  
    return {
      email,
      uuid,
      step,
      isAuthorized
    };
  }
  catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw generateError('Token expired', 'Expired at ' + error.expiredAt, 401);
    }

		throw generateError('Error while verifying token (credentials.verifyToken)', error.message, 400);
  }
}

const verifyPasskeyChallenge = async function (passkeyChallenge) {
  try {
    const { agent, referer, ip } = await verify(passkeyChallenge, passkey_challenge_private_key);

    return {
      agent: agent,
      referer: referer,
      ip: ip
    }
  }
  catch (error) {
    throw generateError('Error while verifying passkey challenge', error.message, 401);
  }
}

const generatePasskeyChallenge = function ({ agent, referer, ip }) {
  return sign({
      agent: agent,
      referer: referer,
      ip: ip,
      salt: Math.random(),
    },
    passkey_challenge_private_key,
    { 
      expiresIn: 5 * 60 // 5 minutes
    }
  );
}

const fakeUser = (email) => {
  return { 
    email: email,
    token: generateUnsignedAccessToken({
        email: email,
        uuid: '00000000-0000-0000-0000-000000000000' // fake uuid
    }),
    isPasswordRequired: true,
    isMFARequired: true,
    hasPasskey: false,
    next: {
      step: 'verify_password',
        url: '/login/password'
    }
  }
}

exports.generatePublicKey = generatePublicKey;
exports.generateTotpSecret = generateTotpSecret;
exports.isTotpValid = isTotpValid;
exports.generateUnsignedAccessToken = generateUnsignedAccessToken;
exports.generateSignedAccessToken = generateSignedAccessToken;
exports.verifyToken = verifyToken;
exports.verifyPasskeyChallenge = verifyPasskeyChallenge;
exports.generatePasskeyChallenge = generatePasskeyChallenge;
exports.fakeUser = fakeUser;
