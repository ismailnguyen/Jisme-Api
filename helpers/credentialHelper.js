exports.getCredentialsFromAuth = function (auth)
{
  const b64auth = (auth.headers.authorization || '').split(' ')[1] || '';
  const [email, user_token] = new Buffer(b64auth, 'base64').toString().split(':');

  var credentials = 
  {
    email: email,
    user_token: user_token
  }

  return credentials;
}
