const { sign, verify } = require('jsonwebtoken');
const { authenticator } = require('otplib');
const { token_master_secret } = require('../config.js');
const { generateError } = require('../helpers/errorHandler.js');

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
      extendedExpiration: extendedExpiration || false
    },
    token_master_secret,
    { 
      expiresIn: extendedExpiration ? '90 days' : '72h'
    }
  );
}

const generateUnsignedAccessToken = function ({ email, uuid}, extendedExpiration) {
  return generateAccessToken(email, uuid, extendedExpiration, false);
}

const generateSignedAccessToken = function ({ email, uuid}, extendedExpiration) {
  return generateAccessToken(email, uuid, extendedExpiration, true);
}

const verifyToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1];

  if (accessToken == null) {
		throw generateError('Error while verifying token (credentialHelper.verifyToken)', 'Access Token not found (credentialHelper.verifyToken)', 401);
  }

  try {
    return {
      email,
      uuid,
      mfaValid,
      extendedExpiration
    } = await verify(accessToken, token_master_secret);
  }
  catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw generateError('Token expired', 'Expired at ' + error.expiredAt, 401);
    }

		throw generateError('Error while verifying token (credentialHelper.verifyToken)', error.message, 400);
  }
}

exports.generateTotpSecret = generateTotpSecret;
exports.isTotpValid = isTotpValid;
exports.generateUnsignedAccessToken = generateUnsignedAccessToken;
exports.generateSignedAccessToken = generateSignedAccessToken;
exports.verifyToken = verifyToken;
