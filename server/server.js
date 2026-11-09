'use strict';

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { port } = require('../utils/config.js');

exports.init = function (routes) {
	const app = express();
	// Vault envelopes (up to 512 KiB of ciphertext, base64url) need a larger
	// bounded parser; it runs first so the default 100 kB parser skips them.
	app.use('/vaults', bodyParser.json({ limit: '1mb' }));
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
