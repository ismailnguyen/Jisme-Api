'use strict';

const { db_repository_type } = require('../../utils/config.js');

let repository = null;
if (db_repository_type === 'db') {
    repository = require('../adapters/dbAdapter.js');
} else if (db_repository_type === 'api') {
    repository = require('../adapters/apiAdapter.js');
} else if (db_repository_type === 'mock') {
    repository = require('../adapters/mockAdapter.js');
} else {
    console.error(`Unknown repository type: ${db_repository_type}, defaulting to database adapter`);
    repository = require('../adapters/dbAdapter.js');
}

// Unable to execute command netlify build with this dynamic requires,
// That is why i had to explicitly require the respective adapter corresponding to the db_repository_type
// const repository = require(`../adapters/${ db_repository_type }Adapter.js`);

const findOne = async function (collection, { filter, projection }) {
    const response = await repository.sendQuery(collection, {
        action: 'findOne',
        filter: filter,
        projection: projection
    });

    if (!response || !response.data || !response.data.document) {
        return null;
    }

    return response.data.document;
}

const count = async function (collection, { filter }) {
    return await repository.sendQuery(collection, {
        action: 'count',
        filter: filter
    });
}

const findAll = async function (collection, { filter, projection, limit, skip, sort }) {
    const response = await repository.sendQuery(collection, {
        action: 'find',
        filter: filter,
        projection: projection,
        limit: limit,
        skip: skip,
        sort: sort
    });

    if (!response || !response.data || !response.data.documents) {
        return [];
    }

    return response.data.documents;
}

const insertOne = async function (collection, { document }) {
    const response = await repository.sendQuery(collection, {
        action: 'insertOne',
        document: document
    });

    let insertedData = document;
    // Give back the id of inserted content
    // Because the insert query doesn't give back the id
    insertedData._id = response.data.insertedId;

    return insertedData;
}

const insertMultiple = async function (collection, { documents }) {
    const response = await repository.sendQuery(collection, {
        action: 'insertMany',
        documents: documents
    });

    return response.insertedIds;
}

const updateOne = async function (collection, { filter, update }) {
    const updateId = filter._id; // Store it before it's changed into ObjectId

    const { matchedCount } = await repository.sendQuery(collection, {
        action: 'updateOne',
        filter: filter,
        update: update
    });

    if (!matchedCount) {
        return null;
    }

    let updatedData = update;
    // Give back the id of updated content
    // Because the update query doesn't give back the id
    updatedData._id = updateId;

    return updatedData;
}

const deleteOne = async function (collection, { filter }) {
    const deletedData = await repository.sendQuery(collection, {
        action: 'deleteOne',
        filter: filter
    });

    return deletedData;
}

exports.count = count;
exports.findOne = findOne;
exports.findAll = findAll;
exports.updateOne = updateOne;
exports.insertOne = insertOne;
exports.insertMultiple = insertMultiple;
exports.deleteOne = deleteOne;
