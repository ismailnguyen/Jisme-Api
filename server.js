const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

exports.init = function (routes)
{	
	const app = express();
	app.use(bodyParser.json());
	app.use(cors());

	routes.registerRoutes(app);
	
	return new Promise(function(resolve, reject) {
		resolve(app);
	});
}

exports.storeDbCollections = function (app, dbConnection)
{
	app.locals.usersCollection = dbConnection.collection('users');
	app.locals.accountsCollection = dbConnection.collection('accounts');
}

exports.storeObjectId = function (app, objectId)
{
	app.locals.ObjectID = objectId;
}

exports.start = function (app)
{
	var server = app.listen(process.env.PORT || 8090, function ()
	{
		var port = server.address().port;
		console.info(`App now running on port ${port}`);
	});
}
