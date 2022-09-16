const {
    update,
    lastUpdateDate
} = require('../../../controllers/userController')

exports.handler = async function (event, context) {
    if (event.httpMethod == 'PUT') {
        const { status, data } = await update(event.headers);

		return {
            statusCode: status,
            body: JSON.stringify(data)
        };
    }

    if (event.httpMethod == 'GET') {
        const { status, data } = await lastUpdateDate(event.headers);

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
