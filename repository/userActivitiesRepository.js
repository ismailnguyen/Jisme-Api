'use strict';

const {
    db_users_activity_log_collection: collection
} = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const findAll = async function ({ query, fields }) {
    return await repository.findAll(collection, {
        filter: query,
        projection: fields
    });
}

const insertOne = async function (value) {
    return await repository.insertOne(collection, {
        document: value
    });
}

const deleteOne = async function ({ query, newValue }) {
    return await repository.deleteOne(collection, {
        filter: query,
        update: newValue
    });
}

exports.findAll = findAll;
exports.insertOne = insertOne;
exports.deleteOne = deleteOne;
