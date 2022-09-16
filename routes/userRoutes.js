'use strict';

module.exports = function (app) {
	const controller = require('../controllers/userController.js');
	
	app
	.route('/users/login')
	.post(async (request, response) => {
		const { status, data } = await controller.login(request.body);

		response.status(status).json(data);
	});

	app
	.route('/users/register')
	.post(async (request, response) => {
		const { status, data } = await controller.register(request.body);

		response.status(status).json(data);
	});

	app
	.route('/users/')
	.put(async (request, response) => {
		const { status, data } = await controller.update(request.headers);

		response.status(status).json(data);
	});

	app
	.route('/users/')
	.get(async (request, response) => {
		const { status, data } = await controller.lastUpdateDate(request.headers);

		response.status(status).json(data);
	});
}