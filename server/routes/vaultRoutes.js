'use strict';
// Client vault envelopes. See docs/vault-envelope-design.md.
const { list, get, put, remove } = require('../../controllers/vaultController.js');

const send = (response, { status, data, headers }) => {
	if (headers) response.set(headers);
	response.status(status).json(data);
};

module.exports = function (app) {
	app
	.route('/vaults')
	.get(async ({ headers }, response) => {
		send(response, await list(headers));
	});

	app
	.route('/vaults/:vaultId')
	.get(async ({ headers, params }, response) => {
		send(response, await get(headers, params));
	})
	.put(async ({ headers, params, body }, response) => {
		send(response, await put(headers, params, body));
	})
	.delete(async ({ headers, params, query }, response) => {
		send(response, await remove(headers, params, query));
	});
}
