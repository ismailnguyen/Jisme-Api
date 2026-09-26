'use strict';

const {
    db_users_collection: collection
} = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const findOne = async function ({ query, fields }) {
    return await repository.findOne(collection, {
        filter: query,
        projection: fields
    });
}

const insertOne = async function (value) {
    return await repository.insertOne(collection, {
        document: value
    });
}

const updateOne = async function ({ query, newValue }) {
    return await repository.updateOne(collection, {
        filter: query,
        update: newValue
    });
}

exports.findOne = findOne;
exports.insertOne = insertOne;
exports.updateOne = updateOne;
