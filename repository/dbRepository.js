const mongodb = require('mongodb');

// Database URL
const db_uri = process.env.MONGODB_URI;

// Database name
const db_name = process.env.MONGODB_DATABASE_NAME;

exports.getDbConnection = function () {
	return mongodb.MongoClient
	.connect(db_uri, {useNewUrlParser: true, useUnifiedTopology: true})
	.then(client => 
	{
		const dbConnection = client.db(db_name);
		console.info('Database connection ready');
		
		objectID = mongodb.ObjectID;

		return new Promise(function (resolve, reject)
		{
			return resolve({ dbConnection: dbConnection, objectID: objectID });
		});
	})
	.catch(error => console.error(error));
}
