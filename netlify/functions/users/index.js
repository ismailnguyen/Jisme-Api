'use strict';

const {
    login,
    verifyPassword,
    verifyPasskey,
    verifyOTP,
    register,
    update,
    getInformation
} = require('../../../controllers/userController')
const passkeys = require('../../../controllers/passkeyController');
const recovery = require('../../../controllers/recoveryController');

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Origin, Authorization, X-Requested-With, Content-Type, Accept',
    'Access-Control-Allow-Methods': 'POST, GET, PUT, DELETE, OPTIONS'
}

const cors_options = async function (request, context) {
    return {
        statusCode: 200,
        headers: CORS_HEADERS,
    }
}

const extractClient = function ({ headers }, context) {
	return {
		agent: headers['user-agent'],
		referer: headers['host'],
		ip: headers['x-nf-client-connection-ip']
	};
}

// New security endpoints send headers (CORS + Retry-After) properly.
const reply = ({ status, data, headers }) => ({
    statusCode: status,
    headers: { ...CORS_HEADERS, ...headers },
    body: JSON.stringify(data)
});

const invalidJson = () => reply({ status: 400, data: { error: { message: 'Invalid user input', reason: 'Body must be JSON' } } });

const parseBody = (body) => {
    if (body === null || body === undefined || body === '') return {};
    return JSON.parse(body);
};

const actionOf = (path) => (typeof path === 'string' ? path.split('users/')[1] : undefined);

// POST users/<action> handled by the passkey / recovery controllers.
const SECURITY_POST_ACTIONS = {
    'passkeys/options': (headers, body, client) => passkeys.enrollmentOptions(headers, body, client),
    'passkeys': (headers, body, client) => passkeys.enroll(headers, body, client),
    'login/passkey/options': (headers, body, client) => passkeys.loginOptions(headers, body, client),
    'recovery': (headers, body, client) => recovery.issue(headers, body, client),
    'recovery/verify': (headers, body, client) => recovery.verify(headers, body, client),
};

const users_delete = async function ({ headers, path, body }, context) {
    const action = actionOf(path) || '';
    const match = /^passkeys\/([A-Za-z0-9_-]+)$/.exec(action);
    if (!match) {
        return { statusCode: 404, headers: CORS_HEADERS, body: 'Action not found' };
    }
    let jsonBody;
    try {
        jsonBody = parseBody(body);
    } catch (_) {
        return invalidJson();
    }
    return reply(await passkeys.remove(headers, { id: match[1] }, jsonBody, extractClient({ headers }, context)));
}

const users_get = async function ({ headers, path }, context) {
    if (actionOf(path) === 'passkeys') {
        return reply(await passkeys.list(headers));
    }

    const { status, data } = await getInformation(headers);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_put = async function ({ headers, body }, context) {
    const { status, data } = await update(headers, JSON.parse(body));

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_post = async function ({ headers, path, body }, context) {
    // Check path if it contains an action
    const action = path.split('users/')[1];

    const client = extractClient({ headers }, context);
    let jsonBody;
    try {
        jsonBody = parseBody(body);
    } catch (_) {
        return invalidJson();
    }

    if (action && Object.prototype.hasOwnProperty.call(SECURITY_POST_ACTIONS, action)) {
        return reply(await SECURITY_POST_ACTIONS[action](headers, jsonBody, client));
    }

    if (action) {
        if (action === 'login') {
            const { status, data } = await login(jsonBody, client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'login/password') {
            const { status, data } = await verifyPassword(headers, jsonBody, client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'login/passkey') {
            return reply(await verifyPasskey(headers, jsonBody, client));
        }

        if (action === 'login/otp') {
            const { status, data } = await verifyOTP(headers, jsonBody, client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'register') {
            const { status, data } = await register(jsonBody, client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }
    }

    return {
        statusCode: 404,
        ...CORS_HEADERS,
        body: 'Action not found'
    }
}

exports.handler = async function (event, context) { 
    const actions = {
        'GET': users_get,
        'PUT': users_put,
        'POST': users_post,
        'DELETE': users_delete,
        'OPTIONS': cors_options
    };

    if (event.httpMethod in actions) {
        return await actions[event.httpMethod](event, context);
    }

    return {
        statusCode: 405,
        ...CORS_HEADERS,
        body: 'Method not allowed'
    }
};
