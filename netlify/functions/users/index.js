const {
    login,
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

const users_get = async function (request) {
    const { status, data } = await lastUpdateDate(request.headers);

    return {
        statusCode: status,
        ...CORS_HEADERS,
        body: JSON.stringify(data)
    };
}

const users_put = async function ({ headers }) {
    const { status, data } = await update(headers);

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
    
    const path = event.path.replace (/\.netlify\/functions\/[^\/]+/, '');
    const segments = path.split('/').filter(e => e);


    switch (event.httpMethod) {
        case 'GET':
            // e.g. GET /.netlify/functions/users
            return users_get(event);
        case 'PUT':
            // e.g. PUT /.netlify/functions/users
            return users_put(event);
        case 'POST':
            // e.g. POST /.netlify/functions/users with a body of key value pair objects, NOT strings
            if (segments.length === 1) {
                if (segments[0] === 'login') {
                    const { status, data } = await login(JSON.parse(event.body));
        
                    return {
                        statusCode: status,
                        ...CORS_HEADERS,
                        body: JSON.stringify(data)
                    };
                }
        
                if (segments[0] === 'register') {
                    const { status, data } = await register(JSON.parse(event.body));
        
                    return {
                        statusCode: status,
                        ...CORS_HEADERS,
                        body: JSON.stringify(data)
                    };
                }
            }
            return {
                statusCode: 500,
                body: 'invalid segments in POST request, must be /.netlify/functions/users/login or /.netlify/functions/users/register'
            }
        case 'OPTIONS':
            // To enable CORS
            const headers = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE'
            };
            return {
                statusCode: 200, // <-- Must be 200 otherwise pre-flight call fails,
                headers,
                body: 'This was a preflight call!'
            }
    }

    return {
        statusCode: 500,
        body: 'Unrecognized HTTP Method, must be one of GET/POST/PUT/OPTIONS'
    };


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
