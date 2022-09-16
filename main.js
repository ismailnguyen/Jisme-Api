const server = require('./server.js');
const routes = require('./routes/index.js');

function main ()
{
	server
		.init(routes)
		.then(app =>
		{
			server.start(app);
			
		});
}

main();