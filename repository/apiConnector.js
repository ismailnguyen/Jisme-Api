const axios = require('axios');
const {
    db_name,
    db_data_source,
    db_api_action_base_url,
    db_api_key
} = require('../config.js');

const sendQuery = async function (collection, { action, filter, projection, limit, document, update }) {
    var data = {
        'dataSource': db_data_source,
        'database': db_name,
        'collection': collection
    };

    if (filter) {
        if (filter._id) {
            filter._id = {
                "$oid": filter._id
            }
        }

        data['filter'] = filter;
    }

    if (document) {
        delete document._id;
        data['document'] = document;
    }

    if (projection) {
        data['projection'] = projection;
    }

    if (action == 'find' && limit) {
        data['limit'] = limit;
    }

    if (update) {
        delete update._id;
        data['update'] = {
            "$set": update
        };
    }

    const request = {
        method: 'post',
        url: `${db_api_action_base_url}${action}`,
        headers: { 
            'api-key': db_api_key, 
            'Content-Type': 'application/json'
        },
        data : JSON.stringify(data),
        maxContentLength: Infinity,
        maxBodyLength: Infinity
    };

    return await axios(request);
}

exports.sendQuery = sendQuery;
