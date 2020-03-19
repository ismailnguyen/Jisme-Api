const MongoClient = require('mongodb').MongoClient;

// Database URL
const db_uri = process.env.MONGODB_URI || 'mongodb://heroku_hq3kkpkr:c3cbgqi47t9gabeb83hl025f78@ds133796.mlab.com:33796/heroku_hq3kkpkr';

// Database name
const db_name = process.env.MONGODB_DATABASE_NAME || 'heroku_hq3kkpkr';

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

