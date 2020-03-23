const errorHandler = require('../helpers/errorHandler.js');
const credentialHelper = require('../helpers/credentialHelper.js');
var ObjectID = require('mongodb').ObjectID;

exports.findAll = function(req, res)
{
 const usersCollection = req.app.locals.usersCollection;
 const accountsCollection = req.app.locals.accountsCollection;
 const credentials = credentialHelper.getCredentialsFromAuth(req);

  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to get accounts';
      errorHandler.handleError(res, message, "No user found");
      return;
    }

    accountsCollection
	.find({user_id: credentials.user_token}).toArray(function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error';
        errorHandler.handleError(res, message, "Failed to get accounts.");
        return;
      }
  
      res.status(200).json(data);
    });
  });
}

exports.create = function(req, res)
{
	const usersCollection = req.app.locals.usersCollection;
	const accountsCollection = req.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(req);

  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to add account';
      errorHandler.handleError(res, message, "No user found");
      return;
    }

    var account = req.body;
	
	delete account._id;
    account.user_id = credentials.user_token;
    account.created_date = new Date();
  
    accountsCollection
	.insertOne(account, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while adding account';
        errorHandler.handleError(res, message, "Failed to add new account.");
        return;
      }
  
      res.status(201).json(data.ops[0]);
    });
  });
}

exports.update = function(req, res)
{
	const usersCollection = req.app.locals.usersCollection;
  const accountsCollection = req.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(req);
  
  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to update account';
      errorHandler.handleError(res, message, "No user found");
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

    accountsCollection
	.updateOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, account, function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while updating account';
        errorHandler.handleError(res, message, "Failed to update account");
        return;
      }
    
      res.status(200).end();
    });
  });
}

exports.remove = function(req, res)
{
	const usersCollection = req.app.locals.usersCollection;
  const accountsCollection = req.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(req);
  
  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to delete account';
      errorHandler.handleError(res, message, "No user found");
      return;
    }

    var account_id = req.params.account_id;
    
    accountsCollection
	.deleteOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, function(err, result)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while deleting account';
        errorHandler.handleError(res, message, "Failed to delete account");
        return;
      }
      
      res.status(204).end();
    });
  });
}