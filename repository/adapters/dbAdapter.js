'use strict';

const connection = require('./dbConnection.js');
const { generateError } = require('../../utils/errors.js');

const {
    ObjectId
} = require('mongodb');

// Vault envelopes use deterministic string _ids (uniqueness without an extra
// index) and only single-document atomic operations. Kept apart from the
// generic path, which rewrites _id into ObjectId and strips it on insert.
const VAULT_COLLECTION = 'vault_envelopes';
const DUPLICATE_KEY = 11000;

const vaultQuery = async function (collection, { action, filter, projection, document, update }) {
    if (action === 'insertOne') {
        try {
            await collection.insertOne(document);
            return { data: { inserted: true } };
        } catch (error) {
            if (error && error.code === DUPLICATE_KEY) return { data: { inserted: false } };
            throw error;
        }
    }
    if (action === 'findOneAndUpdate') {
        return { data: { document: await collection.findOneAndUpdate(filter, { $set: update },
            { returnDocument: 'after', upsert: false, includeResultMetadata: false }) } };
    }
    if (action === 'findOneAndDelete') {
        return { data: { document: await collection.findOneAndDelete(filter, { includeResultMetadata: false }) } };
    }
    if (action === 'findOne') {
        return { data: { document: await collection.findOne(filter) } };
    }
    if (action === 'find') {
        return { data: { documents: await collection.find(filter, { projection }).toArray() } };
    }
    if (action === 'count') {
        return collection.countDocuments(filter);
    }
    throw generateError('Database query error', 'Unsupported vault action', 500);
}

const sendQuery = async function (collectionName, {
    action,
    filter,
    projection,
    limit,
    skip,
    sort,
    document,
    documents,
    update,
    pipeline
}) {
    const dbConnection = await connection.getInstance();
    const collection = dbConnection.collection(collectionName);

    if (collectionName === VAULT_COLLECTION) {
        return vaultQuery(collection, { action, filter, projection, document, update });
    }

    if (filter && filter._id) {
        filter._id = new ObjectId(filter._id);
    }

    if (document && document._id) {
        delete document._id;
    }

    if (update && update._id) {
        delete update._id;
    }

    if (action === 'findOneAndDelete') {
        return {data:{document:await collection.findOneAndDelete(filter, {includeResultMetadata:false})}};
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

    if (action == 'insertMany' && documents) {
        // Prevent additional documents from being inserted if one fails
        const options = { ordered: true };
        return collection.insertMany(documents, options);
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

    if (action == 'insertOne' && document) {
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

    throw generateError('Database query error', 'No db action found', 500);
}

exports.sendQuery = sendQuery;
