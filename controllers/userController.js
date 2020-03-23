const sha256 = require('sha256');
const errorHandler = require('../helpers/errorHandler.js');
var ObjectID = require('mongodb').ObjectID;

exports.login = function(req, res)
{
	const usersCollection = req.app.locals.usersCollection;
	let user = req.body;

  if (user.email == '' || user.password == '')
  {
    errorHandler.handleError(res, "Invalid user input", "Must provide an email and password.", 400);
    return;
  }

  let encryptedPassword = sha256(user.password);

  usersCollection
  .findOne({email: user.email, password: encryptedPassword}, function(err, data)
  {
    if (err)
    {
      let message = err ? err.message : 'Error';
      errorHandler.handleError(res, message, "Failed to find user");
      return;
    }

    if (!data)
    {
      errorHandler.handleError(res, "No user found", "Failed to find user", 404);
      return;
    }

    let loggedUser =
    {
      _id: data._id,
      email: data.email,
      created_date: data.created_date,
      token: data.token,
      last_update_date: data.last_update_date
    };

    res.status(200).json(loggedUser);
  });
}

exports.register = function(req, res)
{
	const usersCollection = req.app.locals.usersCollection;
  var user = req.body;
  user.created_date = new Date();

  if (user.email == '' || user.password == '')
  {
    errorHandler.handleError(res, "Invalid user input", "Must provide an email and password.", 400);
    return;
  }

  // Encrypt user password with SHA256 algorithm
  user.password = sha256(user.password);

  usersCollection
  .findOne({email: user.email, password: user.password}, function(err, data)
  {
    if (err)
    {
      let message = err ? err.message : 'Error';
      errorHandler.handleError(res, message, "User already exists");
      return;
    }

    if (data)
    {
      errorHandler.handleError(res, "User found", "User already exists", 403);
      return;
    }

    // Generate unique token for user
    user.token = sha256(user.email + user.password);

    usersCollection
	.insertOne(user, function(err, data) 
    {
      if (err)
      {
        let message = err ? err.message : 'Error';
        errorHandler.handleError(res, message, "Failed to create new user.");
        return;
      } 

      let registeredUser =
      {
        _id: data.ops[0]._id,
        email: data.ops[0].email,
        created_date: data.ops[0].created_date,
        last_update_date: data.ops[0].last_update_date,
        token: data.ops[0].token
      };

      res.status(201).json(registeredUser);
    });
  });
}

exports.update = function(req, res)
{
  const usersCollection = req.app.locals.usersCollection;
	const credentials = getCredentialsFromAuth(req);

  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to update';
      errorHandler.handleError(res, message, "No user found");
      return;
    }

    var user_id = req.params.user_id;

    var user =
    {
      email: credentials.email,
      password: req.body.password || data.password,
      created_date: data.created_date,
      token: credentials.user_token,
      last_update_date: req.body.last_update_date
    };

    usersCollection
	.updateOne({_id: new ObjectID(user_id), email: credentials.email, token: credentials.user_token}, user, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while updating user';
        errorHandler.handleError(res, message, "Failed to update user");
        return;
      }

      res.status(200).end();
    });
  });
}
