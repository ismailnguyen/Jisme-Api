const {
    login,
    loginWithPasskey,
    verifyMFA,
    register,
    update,
    lastUpdateDate
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

const users_get = async function ({ headers }) {
    const { status, data } = await lastUpdateDate(headers);

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

const users_post = async function ({ headers, path, body }) {
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
            const { status, data } = await loginWithPasskey(JSON.parse(body));

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
