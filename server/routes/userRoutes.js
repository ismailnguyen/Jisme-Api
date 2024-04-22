'use strict';

const {
	login,
	verifyPassword,
	verifyPasskey,
	verifyOTP,
	register,
	update,
	getInformation
} = require('../../controllers/userController.js');

const extractClient = function({ headers, connection }) {
	return {
		agent: headers['user-agent'],
		referer: headers['referer'],
		ip: headers['x-forwarded-for'] || connection.remoteAddress
	};
}

module.exports = function (app) {
	app
	.route('/users/login')
	.post(async ({ headers, connection, body }, response) => {
		var client = extractClient({ headers, connection });

		const { status, data } = await login(body, client);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/login/password')
	.post(async ({ headers, connection, body }, response) => {
		var client = extractClient({ headers, connection });

		const { status, data } = await verifyPassword(headers, body, client);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/login/passkey')
	.post(async ({ headers, connection, body }, response) => {
		var client = extractClient({ headers, connection });

		const { status, data } = await verifyPasskey(headers, body, client);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/login/otp')
	.post(async ({ headers, connection, body }, response) => {
		var client = extractClient({ headers, connection });

		const { status, data } = await verifyOTP(headers, body, client);

		response
			.status(status)
			.json(data);
	});

	app
	.route('/users/register')
	.post(async ({ headers, connection, body }, response) => {
		var client = extractClient({ headers, connection });
		const { status, data } = await register(body, client);

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