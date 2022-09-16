const {
    findAll,
    create,
    find,
    update,
    remove
} = require('../../../controllers/accountController')

exports.handler = async function (event, context) {
    // Check path if it contains an account Id
    const pathSplit = event.path.split('accounts/');
    if (pathSplit.length > 0) {
        const accountId = pathSplit[1];

        if (event.httpMethod == 'GET') {
            const { status, data } = await find(
                event.headers,
                {
                    account_id: accountId
                }
            );
    
            return {
                statusCode: status,
                body: JSON.stringify(data)
            };
        }
    
        if (event.httpMethod == 'PUT') {
            const { status, data } = await update(
                event.headers,
                {
                    account_id: accountId
                }, 
                event.body
            );
    
            return {
                statusCode: status,
                body: JSON.stringify(data)
            };
        }

        if (event.httpMethod == 'DELETE') {
            const { status, data } = await remove(
                event.headers,
                {
                    account_id: accountId
                }
            );
    
            return {
                statusCode: status,
                body: JSON.stringify(data)
            };
        }
    }

    // If no account id found on path
    if (event.httpMethod == 'GET') {
        const { status, data } = await findAll(event.headers);

		return {
            statusCode: status,
            body: JSON.stringify(data)
        };
    }

    if (event.httpMethod == 'POST') {
        const { status, data } = await create(event.headers, event.body);

		return {
            statusCode: status,
            body: JSON.stringify(data)
        };
    }

    return {
        statusCode: 405,
        body: 'Method not allowed'
    }
};
