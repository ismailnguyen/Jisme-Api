'use strict';

const { sign, verify, decode } = require('jsonwebtoken');
const { authenticator } = require('otplib');
const sha256 = require('sha256');
const {
  token_master_secret,
  encryption_public_key_salt
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

const generateAccessToken = function ({ email, uuid, extendedExpiration, step, isAuthorized, client }) {
  return sign({
      email: email,
      uuid: uuid,
      step: step,
      isAuthorized: isAuthorized,
      client: client // client details like agent, referer, ip
    },
    token_master_secret,
    { 
      expiresIn: extendedExpiration ? '90 days' : '72h'
    }
  );
}

const generateUnsignedAccessToken = function ({ email, uuid, step }, client) {
  return generateAccessToken({
    email: email,
    uuid: uuid,
    step: step,
    isAuthorized: false,
    extendedExpiration: false,
    client: client
  });
}

const generateSignedAccessToken = function ({ email, uuid}, extendedExpiration, client) {
  return generateAccessToken({
    email: email,
    uuid: uuid,
    step: 'loggedIn',
    isAuthorized: true,
    extendedExpiration: extendedExpiration,
    client: client
  });
}

const getTokenExpiration = function (token) {
  if (!token) {
    return null;
  }

  const decodedToken = decode(token);

  if (!decodedToken || !decodedToken.exp) {
    return null;
  }

  const expiresAt =
    typeof decodedToken.exp === 'number'
      ? decodedToken.exp
      : parseInt(decodedToken.exp, 10);

  if (Number.isNaN(expiresAt)) {
    return null;
  }

  return new Date(expiresAt * 1000).toISOString();
}

const verifyAccessToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1]; // Remove Bearer

  if (!accessToken) {
		throw generateError('Error while verifying token (credentials.verifyAccessToken)', 'Access Token not found (credentials.verifyAccessToken)', 401);
  }

  try {
    const { email, uuid, step, isAuthorized, client } = await verify(accessToken, token_master_secret);
  
    return {
      email,
      uuid,
      step,
      isAuthorized,
      client: {
        agent: client && client.agent ? client.agent : 'Unknown',
        referer: client && client.referer ? client.referer : 'Unknown',
        ip: client && client.ip ? client.ip : 'Unknown'
      }
    };
  }
  catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw generateError('Token expired', 'Expired at ' + error.expiredAt, 401);
    }

		throw generateError('Error while verifying token (credentials.verifyAccessToken)', error.message, 400);
  }
}

const fakeUser = (email, client) => {
  return { 
    email: email,
    token: generateUnsignedAccessToken(
      {
        email: email,
        uuid: '00000000-0000-0000-0000-000000000000' // fake uuid
      },
      client
    ),
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
exports.verifyAccessToken = verifyAccessToken;
exports.fakeUser = fakeUser;
exports.getTokenExpiration = getTokenExpiration;
