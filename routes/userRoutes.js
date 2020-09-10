'use strict';

module.exports = function (app) {
	const userController = require('../controllers/userController.js');
	
	app.route('/users/login')
		.post(userController.login);
		
	app.route('/users/register')
		.post(userController.register);
		
	app.route('/users/:user_id')
		.put(userController.update);
		
	app.route('/users/:user_id')
		.get(userController.lastUpdateDate);
}