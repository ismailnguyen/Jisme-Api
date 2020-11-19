const errorHandler = require('../helpers/errorHandler.js');
const credentialHelper = require('../helpers/credentialHelper.js');

var ObjectID = require('mongodb').ObjectID;

exports.findAll = function(request, response)
{
 const usersCollection = request.app.locals.usersCollection;
 const accountsCollection = request.app.locals.accountsCollection;
 const credentials = credentialHelper.getCredentialsFromAuth(request);

  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to get accounts';
      return errorHandler.handleError(response, message, "No user found");
    }

    accountsCollection
	.find({user_id: credentials.user_token}).toArray(function(err, data)
    {
      if (err)
      {
        let message = err ? err.message : 'Error';
        return errorHandler.handleError(response, message, "Failed to get accounts.");
      }
  
      response.status(200).json(data);
    });
  });
}

exports.create = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	const accountsCollection = request.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(request);

  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to add account';
      return errorHandler.handleError(response, message, "No user found");
    }

    var account = request.body;
	
	  delete account._id;
    account.user_id = credentials.user_token;
    account.created_date = new Date();
  
    accountsCollection
    .insertOne(account, function(err, data)
      {
        if (err)
        {
          let message = err ? err.message : 'Error while adding account';
          return errorHandler.handleError(response, message, "Failed to add new account.");
        }
    
        response.status(201).json(data.ops[0]);
      });
  });
}

exports.update = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	const accountsCollection = request.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(request);
  
  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to update account';
      return errorHandler.handleError(response, message, "No user found");
    }

    var account_id = request.params.account_id;
    
	var account = request.body;
	account.user_id = credentials.user_token;

    accountsCollection
    .updateOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, { $set: account }, function(err, data)
      {
        if (err)
        {
          let message = err ? err.message : 'Error while updating account';
          return errorHandler.handleError(response, message, "Failed to update account");
        }
      
        response.status(200).end();
      });
    });
}

exports.remove = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	const accountsCollection = request.app.locals.accountsCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(request);
  
  usersCollection
  .findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
  {
    if (err || !data)
    {
      let message = err ? err.message : 'Error while fetching user to delete account';
      return errorHandler.handleError(response, message, "No user found");
    }

    var account_id = request.params.account_id;
    
    accountsCollection
	.deleteOne({_id: new ObjectID(account_id), user_id: credentials.user_token}, function(err, result)
    {
      if (err)
      {
        let message = err ? err.message : 'Error while deleting account';
        return errorHandler.handleError(response, message, "Failed to delete account");
      }
      
      response.status(204).end();
    });
  });
}