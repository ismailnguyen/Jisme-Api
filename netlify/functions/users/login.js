const { login } = require('../../../controllers/userController')

exports.handler = async function (event, context) {
    if (event.httpMethod == 'POST') {
        const { status, data } = await login(event.body);

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
