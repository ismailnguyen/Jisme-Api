'use strict';

const {
	findRecents,
	findAll,
	find,
	create,
	update,
	remove
} = require('../../controllers/accountController.js');

module.exports = function (app) {
	app
	.route('/accounts/recents/')
	.get(async ({ headers }, response) => {
		const { status, data } = await findRecents(headers);

		response
		.status(status)
		.json(data);
	});
	
	app
	.route('/accounts/')
	.get(async ({ headers, query }, response) => {
		const { status, data } = await findAll(headers, query);

		response
		.status(status)
		.json(data);
	});

	app
	.route('/accounts/:account_id')
	.get(async ({ headers, params }, response) => {
		const { status, data } = await find(headers, params);

		response
		.status(status)
		.json(data);
	});

	app
	.route('/accounts/')
	.post(async ({ headers, body }, response) => {
		const { status, data } = await create(headers, body);

		response
		.status(status)
		.json(data);
	});

	app
	.route('/accounts/:account_id')
	.put(async ({ headers, params, body }, response) => {
		const { status, data } = await update(headers, params, body);

		response
		.status(status)
		.json(data);
	});

	app
	.route('/accounts/:account_id')
	.delete(async ({ headers, params }, response) => {
		const { status, data } = await remove(headers, params);

		response
		.status(status)
		.json(data);
	});
}
