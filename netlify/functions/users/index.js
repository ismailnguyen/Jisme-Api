'use strict';

const {
    login,
    requestLoginWithPasskey,
    loginWithPasskey,
    verifyMFA,
    register,
    update,
    getInformation
} = require('../../../controllers/userController')

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Origin, Authorization, X-Requested-With, Content-Type, Accept',
    'Access-Control-Allow-Methods': 'POST, GET, PUT, DELETE, OPTIONS'
}

const cors_options = async function (request) {
    return {
        statusCode: 200,
        headers: CORS_HEADERS,
    }
}

const extractClient = function({ headers }) {
	return {
		agent: headers['user-agent'],
		referer: headers['referer'] || headers['host'],
		ip: headers['x-forwarded-for'],
	};
}

const users_get = async function ({ headers, path }) {
    // Check path if it contains an action
    const action = path.split('users/')[1];

    if (action) {
        if (action === 'login-passkey') {
            var client = extractClient({ headers });
		  
            const { status, data } = await requestLoginWithPasskey(client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }
    }
        
    const { status, data } = await getInformation(headers);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_put = async function ({ headers, body }) {
    const { status, data } = await update(headers, JSON.parse(body));

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_post = async function ({ headers, connection, path, body }) {
    // Check path if it contains an action
    const action = path.split('users/')[1];

    if (action) {
        if (action === 'login') {
            const { status, data } = await login(JSON.parse(body));

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'login-passkey') {
            var client = extractClient({ headers, connection });
            const { status, data } = await loginWithPasskey(JSON.parse(body), client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'verify-mfa') {
            const { status, data } = await verifyMFA(headers, JSON.parse(body));

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        }

        if (action === 'register') {
            const { status, data } = await register(JSON.parse(body));

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
        'OPTIONS': cors_options
    };

    if (event.httpMethod in actions) {
        return await actions[event.httpMethod](event);
    }

    return {
        statusCode: 405,
        ...CORS_HEADERS,
        body: 'Method not allowed'
    }
};
