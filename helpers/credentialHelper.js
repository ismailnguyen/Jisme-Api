const { sign, verify } = require('jsonwebtoken');
const { token_master_secret } = require('../config.js');
const { generateError } = require('../helpers/errorHandler.js');

exports.generateAccessToken = function ({ email, uuid}) {
  return sign(
    {
      data: `${email}:${uuid}`
    },
    token_master_secret,
    { 
      expiresIn: '72h'
    }
  );
}

exports.verifyToken = async function (authorization) {
  const accessToken = authorization && authorization.split(' ')[1];

  if (accessToken == null) {
    throw 'Access Token not found (credentialHelper.verifyToken)';
  }

  try {
    const credentials = await verify(accessToken, token_master_secret);

    const [email, uuid] = credentials.data.split(':');
    
    return {
      email: email,
      uuid: uuid 
    };
  }
  catch (error) {
		throw generateError('Error while verifying token (credentialHelper.verifyToken)', error.message, 400);
  }
}
