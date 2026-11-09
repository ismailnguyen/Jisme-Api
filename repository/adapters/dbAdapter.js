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

// Per-user vault quota: { _id: ownerKey, ids: [vaultId], names: int }.
// reserve = one conditional upsert; release = one conditional $pull.
const QUOTA_COLLECTION = 'vault_quotas';
const isLimit = (value) => Number.isSafeInteger(value) && value >= 1;

const quotaQuery = async function (collection, { action, filter, update }) {
    const _id = filter && filter._id;
    if (typeof _id !== 'string') {
        throw generateError('Database query error', 'Invalid vault quota request', 500);
    }
    if (action === 'findOne') {
        return { data: { document: await collection.findOne({ _id }) } };
    }
    if (action !== 'reserve' && action !== 'release') {
        throw generateError('Database query error', 'Unsupported vault quota action', 500);
    }
    const vaultId = update && update.vaultId;
    const newName = update && update.newName;
    if (typeof vaultId !== 'string' || typeof newName !== 'boolean') {
        throw generateError('Database query error', 'Invalid vault quota request', 500);
    }
    if (action === 'release') {
        const result = await collection.updateOne({ _id, ids: vaultId },
            { $pull: { ids: vaultId }, $inc: { names: newName ? -1 : 0 } });
        return { data: { released: Boolean(result && result.modifiedCount === 1) } };
    }
    const { maxLive, maxNames } = update;
    if (!isLimit(maxLive) || !isLimit(maxNames)) {
        throw generateError('Database query error', 'Invalid vault quota limits', 500);
    }
    const condition = { _id, ids: { $ne: vaultId }, ['ids.' + (maxLive - 1)]: { $exists: false } };
    if (newName) condition.names = { $lt: maxNames };
    const change = { $push: { ids: vaultId }, $inc: { names: newName ? 1 : 0 } };
    // A first-time upsert can race another upsert (E11000) once; after that the
    // document exists, so a repeated E11000 means the condition is false (full).
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            return { data: { document: await collection.findOneAndUpdate(condition, change,
                { upsert: true, returnDocument: 'after', includeResultMetadata: false }) } };
        } catch (error) {
            if (!error || error.code !== DUPLICATE_KEY) throw error;
        }
    }
    return { data: { document: null } };
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
    if (collectionName === QUOTA_COLLECTION) {
        return quotaQuery(collection, { action, filter, update });
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
