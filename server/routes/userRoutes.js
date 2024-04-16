'use strict';

const {
	login,
	requestLoginWithPasskey,
	loginWithPasskey,
	verifyMFA,
	register,
	update,
	getInformation
} = require('../../controllers/userController.js');

module.exports = function (app) {
	app
	.route('/users/login')
	.post(async ({ body }, response) => {
		const { status, data } = await login(body);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/login-passkey')
	.get(async ({ headers, connection }, response) => {
		var client = {
			agent: headers['user-agent'],
			referer: headers['referrer'],
			ip: headers['x-forwarded-for'] || connection.remoteAddress,
		  };
		  
		const { status, data } = await requestLoginWithPasskey(client);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/login-passkey')
	.post(async ({ body }, response) => {
		const { status, data } = await loginWithPasskey(body);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/verify-mfa')
	.post(async ({ headers, body }, response) => {
		const { status, data } = await verifyMFA(headers, body);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/register')
	.post(async ({ body }, response) => {
		const { status, data } = await register(body);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/')
	.put(async ({ headers, body }, response) => {
		const { status, data } = await update(headers, body);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/')
	.get(async ({ headers }, response) => {
		const { status, data } = await getInformation(headers);

		response
			.status(status)
			.json(data);
	});
}