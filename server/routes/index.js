'use strict';

exports.registerRoutes = function (app) {
	const userRoutes = require('./userRoutes.js');
	userRoutes(app);

	const accountRoutes = require('./accountRoutes.js');
	accountRoutes(app);
}