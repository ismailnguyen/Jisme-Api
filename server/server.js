'use strict';

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { port } = require('../utils/config.js');

exports.init = function (routes) {
	const app = express();
	app.use(bodyParser.json());
	app.use(cors());

	routes.registerRoutes(app);
	
	return new Promise(function(resolve, reject) {
		resolve(app);
	});
}

exports.start = function (app) {
	app.listen(port, () => console.info(`App now running on port ${port}`));
}
