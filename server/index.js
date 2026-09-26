'use strict';

const server = require('./server.js');
const routes = require('./routes/index.js');

const main = () => {
	server
	.init(routes)
	.then(server.start);
}

main();
