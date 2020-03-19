const express = require('express');
const cors = require('cors')
const bodyParser = require('body-parser');
const sha256 = require('sha256');
const MongoClient = require('mongodb').MongoClient;

const app = express();
app.use(bodyParser.json());
app.use(cors());

// DATABASE CONFIGURATION BELOW

// Create a database variable outside of the database connection callback to reuse the connection pool in app.
var db;

// Database URL
var db_uri = process.env.MONGODB_URI;
// Database name
var db_name = process.env.MONGODB_DATABASE_NAME;

// Database collections
const USERS_COLLECTION = 'users';
const ACCOUNTS_COLLECTION = 'accounts';

MongoClient.connect(db_uri, function(err, client) {
	if(err)
		throw err;
	
	db = client.db(db_name);
	console.log("Database connection ready");

	// Initialize the app.
	var server = app.listen(process.env.PORT || 8090, function ()
	{
		var port = server.address().port;
		console.log("App now running on port", port);
	});
});

// API ROUTES BELOW

var USERS_API_URL = '/users';
var ACCOUNTS_API_URL = '/accounts';

// Generic error handler used by all endpoints.
function handleError(res, reason, message, code)
{
  console.log('ERROR: ' + message + '(' + reason + ')');
  res
  .status(code || 500)
  .json(
	{
		"error": {
			"message": message,
			"reason": reason
		}
	});
}

function getCredentialsFromAuth(auth)
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

/*  "/users"
 *    GET: retrieves user using his email and password
 *    POST: creates a new user
 *    PUT: update an existing user
 */

app.post(USERS_API_URL + "/login", function(req, res)
{
  let user = req.body;

  if (user.email == '' || user.password == '')
  {
    handleError(res, "Invalid user input", "Must provide an email and password.", 400);
    return;
  }

  let encryptedPassword = sha256(user.password);

  db.collection(USERS_COLLECTION)
  .findOne({email: user.email, password: encryptedPassword}, function(err, data)
  {
    if (err)
    {
      let message = err ? err.message : 'Error';
      handleError(res, message, "Failed to find user");
      return;
    }

    if (!data)
    {
      handleError(res, "No user found", "Failed to find user", 404);
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
});

app.post(USERS_API_URL + "/register", function(req, res)
{
  var user = req.body;
  user.created_date = new Date();

  if (user.email == '' || user.password == '')
  {
    handleError(res, "Invalid user input", "Must provide an email and password.", 400);
    return;
  }

  // Encrypt user password with SHA256 algorithm
  user.password = sha256(user.password);

  db.collection(USERS_COLLECTION)
  .findOne({email: user.email, password: user.password}, function(err, data)
  {
    if (err)
    {
      let message = err ? err.message : 'Error';
      handleError(res, message, "User already exists");
      return;
    }

    if (data)
    {
      handleError(res, "User found", "User already exists", 403);
      return;
    }

    // Generate unique token for user
    user.token = sha256(user.email + user.password);

    db.collection(USERS_COLLECTION).insertOne(user, function(err, data) 
    {
      if (err)
      {
        let message = err ? err.message : 'Error';
        handleError(res, message, "Failed to create new user.");
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
});

app.put(USERS_API_URL + "/:user_id", function(req, res)
{
  var credentials = getCredentialsFromAuth(req);

  db.collection(USERS_COLLECTION)
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to update';
      handleError(res, message, "No user found");
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

    db.collection(USERS_COLLECTION).updateOne({_id: new ObjectID(user_id), email: credentials.email, token: credentials.user_token}, user, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while updating user';
        handleError(res, message, "Failed to update user");
        return;
      }

      res.status(200).end();
    });
  });
});

/*  "/accounts/:user_token"
 *    GET: find accounts by user token
 *    POST: add new account for user
 *    PUT: update account by user token
 *    DELETE: deletes account by user token
 */

app.get(ACCOUNTS_API_URL, function(req, res)
{
  var credentials = getCredentialsFromAuth(req);

  db.collection(USERS_COLLECTION)
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to get accounts';
      handleError(res, message, "No user found");
      return;
    }

    db.collection(ACCOUNTS_COLLECTION).find({user_id: credentials.user_token}).toArray(function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error';
        handleError(res, message, "Failed to get accounts.");
        return;
      }
  
      res.status(200).json(data);
    });
  });
});

app.post(ACCOUNTS_API_URL, function(req, res)
{
  var credentials = getCredentialsFromAuth(req);

  db.collection(USERS_COLLECTION)
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to add account';
      handleError(res, message, "No user found");
      return;
    }

    var account = req.body;
	
	delete account._id;
    account.user_id = credentials.user_token;
    account.created_date = new Date();
  
    db.collection(ACCOUNTS_COLLECTION).insertOne(account, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while adding account';
        handleError(res, message, "Failed to add new account.");
        return;
      }
  
      res.status(201).json(data.ops[0]);
    });
  });
});

app.put(ACCOUNTS_API_URL + "/:account_id", function(req, res)
{
  var credentials = getCredentialsFromAuth(req);
  
  db.collection(USERS_COLLECTION)
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to update account';
      handleError(res, message, "No user found");
      return;
    }

    var account_id = req.params.account_id;
    
    var account =
    {
      platform: req.body.platform,
      login: req.body.login,
      password: req.body.password,
      tags: req.body.tags,
      user_id: credentials.user_token,
      created_date: req.body.created_date
    };

    db.collection(ACCOUNTS_COLLECTION).updateOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, account, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while updating account';
        handleError(res, message, "Failed to update account");
        return;
      }
    
      res.status(200).end();
    });
  });
});

app.delete(ACCOUNTS_API_URL + "/:account_id", function(req, res)
{
  var credentials = getCredentialsFromAuth(req);
  
  db.collection(USERS_COLLECTION)
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to delete account';
      handleError(res, message, "No user found");
      return;
    }

    var account_id = req.params.account_id;
    
    db.collection(ACCOUNTS_COLLECTION).deleteOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, function(err, result)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while deleting account';
        handleError(res, message, "Failed to delete account");
        return;
      }
      
      res.status(204).end();
    });
  });
});
