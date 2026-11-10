'use strict';
// Passkey (PRF) vault unlock. Registered before vaultRoutes so these literal
// paths are matched ahead of '/vaults/:vaultId'.
const { unlockOptions, unlockPasskey, lock } = require('../../controllers/vaultController.js');

const send = (response, { status, data, headers }) => {
	if (headers) response.set(headers);
	response.status(status).json(data);
};

module.exports = function (app) {
	app
	.route('/vaults/unlock/passkey/options')
	.post(async ({ headers, body }, response) => {
		send(response, await unlockOptions(headers, body || {}));
	});

	app
	.route('/vaults/unlock/passkey')
	.post(async ({ headers, body }, response) => {
		send(response, await unlockPasskey(headers, body || {}));
	});

	app
	.route('/vaults/lock')
	.post(async ({ headers, body }, response) => {
		send(response, await lock(headers, body || {}));
	});
}
