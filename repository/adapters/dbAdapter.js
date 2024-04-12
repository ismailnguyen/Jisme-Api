'use strict';

const connection = require('./dbConnection.js');

const {
    ObjectId
} = require('mongodb');

const sendQuery = async function (collectionName, {
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
    const dbConnection = await connection.getInstance();
    const collection = dbConnection.collection(collectionName);

    if (filter && filter._id) {
        filter._id = new ObjectId(filter._id);
    }

    if (document && document._id) {
        delete document._id;
    }

    if (update && update._id) {
        delete update._id;
    }

    if (action === 'count') {
        return collection.countDocuments(filter);
    }

    if (action == 'findOne') {
        return {
            data: {
                document: collection.findOne(filter)
            }
        };
    }

    if (action == 'find') {
        let options  = {};

        if (projection) {
            options['projection'] = projection;
        }

        if (limit) {
            options['limit'] = Number(limit);
        }

        if (skip) {
            options['skip'] = Number(skip);
        }

        if (sort) {
            options['sort'] = sort;
        }

        return {
            data: {
                documents: collection.find(filter, options).toArray()
            }
        };
    }

    if (action == 'aggregate') {
        return collection.aggregate(pipeline);
    }

    if (action == 'insertOne') {
        // If there is already an id, remove it before inserting
        // Because databse will generate it
        delete document._id;

        const response = await collection.insertOne(document);
        return {
            data: {
                insertedId: response.insertedId
            }
        };
    }

    if (action == 'updateOne') {
        return collection.updateOne(filter, { $set: update });
    }

    if (action == 'deleteOne') {
        return collection.deleteOne(filter);
    }
}

exports.sendQuery = sendQuery;
