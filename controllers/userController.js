const sha256 = require('sha256');
const errorHandler = require('../helpers/errorHandler.js');
const credentialHelper = require('../helpers/credentialHelper.js');

var ObjectID = require('mongodb').ObjectID;

exports.login = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	let user = request.body;

	if (user.email == '' || user.password == '')
	{
		return errorHandler.handleError(response, "Invalid user input", "Must provide an email and password.", 400);
	}

	let encryptedPassword = sha256(user.password);

	usersCollection
	.findOne({email: user.email, password: encryptedPassword}, function(err, data)
	{
		if (err)
		{
			let message = err ? err.message : 'Error';
			return errorHandler.handleError(response, message, "Failed to find user");
		}

		if (!data)
		{
			return errorHandler.handleError(response, "No user found", "Failed to find user", 404);
		}

		let loggedUser =
		{
			_id: data._id,
			email: data.email,
			created_date: data.created_date,
			token: data.token,
			last_update_date: data.last_update_date
		};

		response.status(200).json(loggedUser);
	});
}

exports.register = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	var user = request.body;
	user.created_date = new Date();

	if (user.email == '' || user.password == '')
	{
		return errorHandler.handleError(response, "Invalid user input", "Must provide an email and password.", 400);
	}

	// Encrypt user password with SHA256 algorithm
	user.password = sha256(user.password);

	usersCollection
	.findOne({email: user.email, password: user.password}, function(err, data)
	{
		if (err)
		{
			let message = err ? err.message : 'Error';
			return errorHandler.handleError(response, message, "User already exists");
		}

		if (data)
		{
			return errorHandler.handleError(response, "User found", "User already exists", 403);
		}

		// Generate unique token for user
		user.token = sha256(user.email + user.password);

		usersCollection
		.insertOne(user, function(err, data) 
		{
			if (err)
			{
				let message = err ? err.message : 'Error';
				return errorHandler.handleError(response, message, "Failed to create new user.");
			} 

			let registeredUser =
			{
				_id: data.ops[0]._id,
				email: data.ops[0].email,
				created_date: data.ops[0].created_date,
				last_update_date: data.ops[0].last_update_date,
				token: data.ops[0].token
			};

			response.status(201).json(registeredUser);
		});
	});
}

exports.update = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(request);

	usersCollection
	.findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
	{
		if (err || !data)
		{
			let message = err ? err.message : 'Error while fetching user to update';
			return errorHandler.handleError(response, message, "No user found");
		}

		var user_id = request.params.user_id;

		var user =
		{
			email: credentials.email,
			password: request.body.password || data.password,
			created_date: data.created_date,
			token: credentials.user_token,
			last_update_date: request.body.last_update_date || new Date()
		};

		usersCollection
		.updateOne({_id: new ObjectID(user_id), email: credentials.email, token: credentials.user_token}, { $set: user }, function(err, data)
		{
			if (err)
			{
				let message = err ? err.message : 'Error while updating user';
				return errorHandler.handleError(response, message, "Failed to update user");
			}

			response.status(200).end();
		});
	});
}

exports.lastUpdateDate = function(request, response)
{
	const usersCollection = request.app.locals.usersCollection;
	const credentials = credentialHelper.getCredentialsFromAuth(request);

	usersCollection
	.findOne({email: credentials.email, token: credentials.user_token}, function(err, data)
	{
		if (err || !data)
		{
			let message = err ? err.message : 'Error while fetching user to find';
			return errorHandler.handleError(response, message, "No user found");
		}

		var user =
		{
			last_update_date: data.last_update_date
		};

		response.status(200).json(user);
	});
}
