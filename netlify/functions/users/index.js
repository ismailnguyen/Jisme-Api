const {
    login,
    register,
    update,
    lastUpdateDate
} = require('../../../controllers/userController')

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept',
    'Content-Type': 'application/json',
    'Access-Control-Allow-Methods': '*',
    'Access-Control-Max-Age': '2592000',
    'Access-Control-Allow-Credentials': true
}

const cors_options = function () {
    return {
        statusCode: 204,
        CORS_HEADERS
      };
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
    const { status, data } = await update(headers, body);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_post = async function ({ path, body }) {
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
    if (event.httpMethod === 'OPTIONS') {
        return cors_options();
    }

    const actions = {
        'GET': users_get,
        'PUT': users_put,
        'POST': users_post
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
