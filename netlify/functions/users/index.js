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

const users_get = async function ({ headers, path }, context) {
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
    const jsonBody = JSON.parse(body);

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
            const { status, data } = await verifyPasskey(headers, jsonBody, client);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
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
