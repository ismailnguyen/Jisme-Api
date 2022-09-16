const {
    login,
    register,
    update,
    lastUpdateDate
} = require('../../../controllers/userController')

const users_get = async function (request) {
    const { status, data } = await lastUpdateDate(request.headers);

    return {
        statusCode: status,
        body: JSON.stringify(data)
    };
}

const users_put = async function ({ headers }) {
    const { status, data } = await update(headers);

    return {
        statusCode: status,
        body: JSON.stringify(data)
    };
}

const users_post = async function ({ path, body }) {
    // Check path if it contains an action
    const pathSplit = path.split('users/');
    if (pathSplit.length > 0) {
        const action = pathSplit[1];

        if (action === 'login') {
            const { status, data } = await login(JSON.parse(body));

            return {
                statusCode: status,
                body: JSON.stringify(data)
            };
        }

        if (action === 'register') {
            const { status, data } = await register(JSON.parse(body));

            return {
                statusCode: status,
                body: JSON.stringify(data)
            };
        }
    }

    return {
        statusCode: 404,
        body: 'Action not found'
    }
}

exports.handler = async function (event, context) {
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
        body: 'Method not allowed'
    }
};
