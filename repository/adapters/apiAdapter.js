'use strict';

const axios = require('axios');
const { generateError } = require('../../utils/errors.js');

const {
    db_name,
    db_data_source,
    db_api_action_base_url,
    db_api_key
} = require('../../utils/config.js');

const count = async function (collection, { filter }) {
    const response = await sendQuery(collection,
    {
        action: 'aggregate',
        pipeline: [
            { $match: filter },
            { $count: 'count' }
        ]
    });

    if (!response
        || !response.data
        || !response.data.documents
        || response.data.documents.length === 0) {
        return 0;
    }

    return response.data.documents[0].count;
}

const sendQuery = async function (collection, {
    action,
    filter,
    projection,
    limit,
    skip,
    sort,
    document,
    update,
    pipeline
 }) {
    var data = {
        'dataSource': db_data_source,
        'database': db_name,
        'collection': collection
    };

    if (action === 'count') {
        return count(collection, { filter });
    }

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

    if (action == 'find') {
        if (limit) {
            data['limit'] = Number(limit);
        }
    
        if (skip) {
            data['skip'] = Number(skip);
        }
    
        if (sort) {
            data['sort'] = sort;
        }
    }

    if (update) {
        delete update._id;
        data['update'] = {
            "$set": update
        };
    }

    if (pipeline) {
        data['pipeline'] = pipeline;
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

    try {
        return await axios(request);
    }
    catch (error) {
        if (error.response && error.response.data) {
            throw generateError(error.message, error.response.data, 500);
        }

        throw generateError('Database connection error', error.message, 500);
    }
}

exports.sendQuery = sendQuery;
