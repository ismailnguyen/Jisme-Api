const {
    findAll,
    create,
    find,
    update,
    remove
} = require('../../../controllers/accountController')

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Origin, Authorization, X-Requested-With, Content-Type, Accept',
    'Access-Control-Allow-Methods': 'POST, GET, PUT, DELETE'
}

const cors_options = async function (request) {
    return {
        statusCode: 200,
        headers: CORS_HEADERS,
    }
}

const accounts_get = async function (request) {
    // Check path if it contains an account Id
    const accountId = request.path.split('accounts/')[1];

    if (accountId) {
        const { status, data } = await find(
            request.headers,
            {
                account_id: accountId
            }
        );

        return {
            statusCode: status,
            ...CORS_HEADERS,
            body: JSON.stringify(data)
        };
    }

    // If no account id found on path
    const { status, data } = await findAll(request.headers);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_post = async function (request) {
    const { status, data } = await create(request.headers, request.body);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_put = async function (request) {
    const { status, data } = await update(
        request.headers,
        {
            account_id: accountId
        }, 
        request.body
    );

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_delete = async function (request) {
    const { status, data } = await remove(
        request.headers,
        {
            account_id: accountId
        }
    );

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

exports.handler = async function (event, context) {
    const actions = {
        'GET': accounts_get,
        'POST': accounts_post,
        'PUT': accounts_put,
        'DELETE': accounts_delete,
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
