const { db_uri, db_name } = require('../config.js');
const MongoClient = require('mongodb').MongoClient;

exports.getDbConnection = function () {
	return MongoClient
	.connect(db_uri, {useNewUrlParser: true, useUnifiedTopology: true})
	.then(client => 
	{
		const dbConnection = client.db(db_name);
		console.info('Database connection ready');
		
		return new Promise(function (resolve, reject)
		{
			return resolve(dbConnection);
		});
	})
	.catch(error => console.error(error));
}
