'use strict';

const { sign, verify } = require('jsonwebtoken');
const { authenticator } = require('otplib');
const sha256 = require('sha256');
const { token_master_secret, encryption_public_key_salt } = require('./config.js');
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

const generateAccessToken = function (email, uuid, extendedExpiration, mfaValid) {
  return sign(
    {
      email: email,
      uuid: uuid,
      mfaValid: mfaValid,
    },
    token_master_secret,
    { 
      expiresIn: extendedExpiration ? '90 days' : '72h'
    }
  );
}

const generateUnsignedAccessToken = function ({ email, uuid}) {
  return generateAccessToken(email, uuid, false, false);
}

const generateSignedAccessToken = function ({ email, uuid}, extendedExpiration) {
  return generateAccessToken(email, uuid, extendedExpiration, true);
}

const verifyToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1]; // Remove Bearer

  if (!accessToken) {
		throw generateError('Error while verifying token (credentials.verifyToken)', 'Access Token not found (credentials.verifyToken)', 401);
  }

  try {
    const { email, uuid, mfaValid }  = await verify(accessToken, token_master_secret);
  
    return {
      email,
      uuid,
      mfaValid
    };
  }
  catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw generateError('Token expired', 'Expired at ' + error.expiredAt, 401);
    }

		throw generateError('Error while verifying token (credentials.verifyToken)', error.message, 400);
  }
}

exports.generatePublicKey = generatePublicKey;
exports.generateTotpSecret = generateTotpSecret;
exports.isTotpValid = isTotpValid;
exports.generateUnsignedAccessToken = generateUnsignedAccessToken;
exports.generateSignedAccessToken = generateSignedAccessToken;
exports.verifyToken = verifyToken;
