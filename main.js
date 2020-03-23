const server = require('./server.js');
const routes = require('./routes/index.js');
const repository = require('./repository/dbRepository.js');

function main ()
{
	server
		.init(routes)
		.then(app =>
		{
			repository.getDbConnection()
			.then(({ dbConnection, objectId }) => {
				server.storeDbCollections(app, dbConnection);
				server.storeObjectId(app, objectId);
				
				server.start(app);
			});		
		});
}

main();