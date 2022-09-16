'use strict';

module.exports = function (app) {
	const controller = require('../controllers/accountController.js');
	
	app
	.route('/accounts/')
	.get(async (request, response) => {
		const { status, data } = await controller.findAll(request.headers);

		response.status(status).json(data);
	});

	app
	.route('/accounts/')
	.post(async (request, response) => {
		const { status, data } = await controller.create(request.headers, request.body);

		response.status(status).json(data);
	});

	app
	.route('/accounts/:account_id')
	.get(async (request, response) => {
		const { status, data } = await controller.find(request.headers, request.params);

		response.status(status).json(data);
	});

	app
	.route('/accounts/:account_id')
	.put(async (request, response) => {
		const { status, data } = await controller.update(request.headers, request.params, request.body);

		response.status(status).json(data);
	});

	app
	.route('/accounts/:account_id')
	.delete(async (request, response) => {
		const { status, data } = await controller.remove(request.headers, request.params);

		response.status(status).json(data);
	});
}
