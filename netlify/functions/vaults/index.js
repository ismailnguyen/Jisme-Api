'use strict';
// Client vault envelopes. See docs/vault-envelope-design.md.
const { list, get, put, remove, unlockOptions, unlockPasskey, lock } = require('../../../controllers/vaultController');

// POST-only actions; any other POST target stays 405.
const POST_ACTIONS = {
    'unlock/passkey/options': unlockOptions,
    'unlock/passkey': unlockPasskey,
    'lock': lock,
};

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Origin, Authorization, X-Requested-With, Content-Type, Accept',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
};

const reply = ({ status, data, headers }) => ({
    statusCode: status,
    headers: { ...CORS_HEADERS, ...headers },
    body: JSON.stringify(data)
});

const invalid = (reason) => reply({ status: 400, data: { error: { message: 'Invalid vault input', reason } } });

// '/.netlify/functions/vaults[/<id>]' or '/func/vaults[/<id>]' -> '' | '<id>'
// Any extra segment is kept so the service rejects it as an invalid vaultId.
const vaultIdFrom = (path) => {
    const index = typeof path === 'string' ? path.indexOf('/vaults') : -1;
    if (index < 0) return null;
    const rest = path.slice(index + '/vaults'.length);
    if (rest !== '' && !rest.startsWith('/')) return null;
    return rest.slice(1);
};

exports.handler = async function ({ httpMethod, path, headers, body, queryStringParameters }) {
    if (httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: CORS_HEADERS };
    }

    const vaultId = vaultIdFrom(path);
    if (vaultId === null) {
        return invalid('Unknown vault path');
    }

    if (httpMethod === 'GET') {
        return reply(vaultId === '' ? await list(headers) : await get(headers, { vaultId }));
    }

    if (httpMethod === 'PUT') {
        let payload;
        try {
            payload = JSON.parse(body);
        } catch (_) {
            return invalid('Body must be JSON');
        }
        return reply(await put(headers, { vaultId }, payload));
    }

    if (httpMethod === 'POST' && Object.prototype.hasOwnProperty.call(POST_ACTIONS, vaultId)) {
        let payload;
        try {
            payload = body ? JSON.parse(body) : {};
        } catch (_) {
            return invalid('Body must be JSON');
        }
        return reply(await POST_ACTIONS[vaultId](headers, payload));
    }

    if (httpMethod === 'DELETE') {
        return reply(await remove(headers, { vaultId }, queryStringParameters || {}));
    }

    return { statusCode: 405, headers: CORS_HEADERS, body: 'Method not allowed' };
};
