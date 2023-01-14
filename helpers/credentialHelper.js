const { sign, verify } = require('jsonwebtoken');
const { token_master_secret } = require('../config.js');
const { generateError } = require('../helpers/errorHandler.js');

exports.generateAccessToken = function ({ email, uuid}, extendedExpiration) {
  return sign(
    {
      email: email,
      uuid: uuid
    },
    token_master_secret,
    { 
      expiresIn: extendedExpiration ? '90 days' : '72h'
    }
  );
}

exports.verifyToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1];

  if (accessToken == null) {
    throw 'Access Token not found (credentialHelper.verifyToken)';
  }

  try {
    const { email, uuid} = await verify(accessToken, token_master_secret);

    return {
      email: email,
      uuid: uuid 
    };
  }
  catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw generateError('Token expired', 'Expired at ' + error.expiredAt, 401);
    }

		throw generateError('Error while verifying token (credentialHelper.verifyToken)', error.message, 400);
  }
}
