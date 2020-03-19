'use strict';

module.exports = function (app) {
	const accountController = require('../controllers/accountController.js');
	
	app.route('/accounts')
		.get(accountController.findAll)
		.post(accountController.create);
	
	app.route('/accounts/:account_id')
		.put(accountController.update)
		.delete(accountController.remove);
}