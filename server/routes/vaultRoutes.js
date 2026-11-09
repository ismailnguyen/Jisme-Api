'use strict';
// Client vault envelopes. See docs/vault-envelope-design.md.
const { list, get, put, remove } = require('../../controllers/vaultController.js');

module.exports = function (app) {
	app
	.route('/vaults')
	.get(async ({ headers }, response) => {
		const { status, data } = await list(headers);
		response.status(status).json(data);
	});

	app
	.route('/vaults/:vaultId')
	.get(async ({ headers, params }, response) => {
		const { status, data } = await get(headers, params);
		response.status(status).json(data);
	})
	.put(async ({ headers, params, body }, response) => {
		const { status, data } = await put(headers, params, body);
		response.status(status).json(data);
	})
	.delete(async ({ headers, params, query }, response) => {
		const { status, data } = await remove(headers, params, query);
		response.status(status).json(data);
	});
}
