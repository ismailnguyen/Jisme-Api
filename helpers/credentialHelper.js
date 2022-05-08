exports.getCredentialsFromAuth = function (auth)
{
  const b64auth = (auth.headers.authorization || '').split(' ')[1] || '';
  const [email, uuid] = new Buffer(b64auth, 'base64').toString().split(':');

  return {
    email: email,
    uuid: uuid
  };
}
