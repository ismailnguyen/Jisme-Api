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
const passkeys = require('../../controllers/passkeyController.js');
const recovery = require('../../controllers/recoveryController.js');

const send = (response, { status, data, headers }) => {
	if (headers) response.set(headers);
	response.status(status).json(data);
};

const extractClient = function({ headers, connection }) {
	return {
		agent: headers['user-agent'],
		referer: headers['origin'],
		ip: headers['x-forwarded-for'] || connection.remoteAddress
	};
}

module.exports = function (app) {
	// Verified passkey enrollment (fresh password+MFA session).
	app
	.route('/users/passkeys/options')
	.post(async ({ headers, connection, body }, response) => {
		send(response, await passkeys.enrollmentOptions(headers, body || {}, extractClient({ headers, connection })));
	});

	app
	.route('/users/passkeys')
	.post(async ({ headers, connection, body }, response) => {
		send(response, await passkeys.enroll(headers, body || {}, extractClient({ headers, connection })));
	})
	.get(async ({ headers }, response) => {
		send(response, await passkeys.list(headers));
	});

	app
	.route('/users/passkeys/:id')
	.delete(async ({ headers, connection, params, body }, response) => {
		send(response, await passkeys.remove(headers, { id: params.id }, body || {}, extractClient({ headers, connection })));
	});

	// Passkey login challenge (pre-auth token from /users/login).
	app
	.route('/users/login/passkey/options')
	.post(async ({ headers, connection, body }, response) => {
		send(response, await passkeys.loginOptions(headers, body || {}, extractClient({ headers, connection })));
	});

	// Recovery codes (fresh password+MFA session).
	app
	.route('/users/recovery')
	.post(async ({ headers, connection, body }, response) => {
		send(response, await recovery.issue(headers, body || {}, extractClient({ headers, connection })));
	});

	app
	.route('/users/recovery/verify')
	.post(async ({ headers, connection, body }, response) => {
		send(response, await recovery.verify(headers, body || {}, extractClient({ headers, connection })));
	});

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

		send(response, await verifyPasskey(headers, body, client));
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