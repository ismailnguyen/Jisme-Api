const {
    findRecents,
    findAll,
    create,
    find,
    update,
    remove
} = require('../../../controllers/accountController')

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

const accounts_get = async function ({ path, headers }) {
    // Check path if it contains an account Id
    const accountId = path.split('accounts/')[1];

    if (accountId) {
        if (accountId === 'recents/') {
            const { status, data } = await findRecents(headers);

            return {
                statusCode: status,
                ...CORS_HEADERS,
                body: JSON.stringify(data)
            };
        } else {
            const { status, data } = await find(
                headers,
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
    }

    // If no account id found on path
    const { status, data } = await findAll(headers);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_post = async function ({ headers, body }) {
    const { status, data } = await create(headers, JSON.parse(body));

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_put = async function ({ path, headers, body }) {
    // Check path if it contains an account Id
    const accountId = path.split('accounts/')[1];

    if (!accountId) {
        return {
            statusCode: 40,
            ...CORS_HEADERS,
            body: 'bad request, missing account id'
        };
        
    }

    const { status, data } = await update(
        headers,
        {
            account_id: accountId
        }, 
        JSON.parse(body)
    );

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const accounts_delete = async function ({ path, headers }) {
    // Check path if it contains an account Id
    const accountId = path.split('accounts/')[1];

    if (!accountId) {
        return {
            statusCode: 40,
            ...CORS_HEADERS,
            body: 'bad request, missing account id'
        };
    }

    const { status, data } = await remove(
        headers,
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
