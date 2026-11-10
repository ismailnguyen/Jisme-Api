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

const AMR_VALUES = ['pwd', 'otp', 'webauthn'];
const sanitizeAmr = (amr) => Array.isArray(amr)
  ? AMR_VALUES.filter((value) => amr.includes(value))
  : undefined;

const generateAccessToken = function ({ email, uuid, extendedExpiration, step, isAuthorized, client, authTime, amr }) {
  const payload = {
      email: email,
      uuid: uuid,
      step: step,
      isAuthorized: isAuthorized,
      client: client // client details like agent, referer, ip
    };

  // auth_time deliberately records completed authentication time.
  // It is only set on fully authenticated tokens, never inferred from
  // issuance (iat) or refresh time. Pre-auth tokens omit it.
  if (authTime !== undefined && authTime !== null) {
    payload.auth_time = authTime;
  }

  // amr (RFC 8176 style) records HOW the session was authenticated:
  // 'pwd' (password), 'otp' (TOTP), 'webauthn' (verified passkey). Step-up
  // endpoints (passkey enrollment, recovery) require 'pwd' (+ 'otp' with MFA).
  const methods = sanitizeAmr(amr);
  if (methods && methods.length) {
    payload.amr = methods;
  }

  return sign(payload,
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

const generateSignedAccessToken = function ({ email, uuid}, extendedExpiration, client, { amr } = {}) {
  return generateAccessToken({
    email: email,
    uuid: uuid,
    step: 'loggedIn',
    isAuthorized: true,
    extendedExpiration: extendedExpiration,
    client: client,
    authTime: Math.floor(Date.now() / 1000),
    amr: amr
  });
}

// Trusted session resolver for security ceremonies (e.g. WebAuthn
// enrollment). Fails closed unless the token is a fully authenticated
// session carrying a deliberate auth_time claim: pre-auth tokens and
// legacy tokens issued before auth_time existed must reauthenticate.
// The freshness window (auth_time age) is enforced by the ceremony layer.
const generateFreshSessionResolver = function () {
  return async function resolveFreshSession(authorization) {
    const session = await verifyAccessToken(authorization);

    if (session.isAuthorized !== true || !session.uuid
        || !Number.isSafeInteger(session.auth_time)) {
      throw generateError(
        'Error while resolving session (credentials.generateFreshSessionResolver)',
        'A fresh authenticated session is required',
        401
      );
    }

    return session;
  };
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
    const { email, uuid, step, isAuthorized, client, auth_time, amr } = await verify(accessToken, token_master_secret);
  
    return {
      email,
      uuid,
      step,
      isAuthorized,
      auth_time: Number.isSafeInteger(auth_time) ? auth_time : undefined,
      amr: sanitizeAmr(amr) || [],
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
exports.generateFreshSessionResolver = generateFreshSessionResolver;
exports.fakeUser = fakeUser;
exports.getTokenExpiration = getTokenExpiration;
