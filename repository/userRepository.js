'use strict';

const { db_users_collection } = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const findOne = async function ({ query, fields }) {
    return await repository.findOne(db_users_collection,
    {
        filter: query,
        projection: fields
    });
}

const insertOne = async function (value) {
    return await repository.insertOne(db_users_collection, 
    {
        document: value
    });
}

const updateOne = async function ({ query, newValue }) {
    return await repository.updateOne(db_users_collection,
    {
        filter: query,
        update: newValue
    });
}

exports.findOne = findOne;
exports.insertOne = insertOne;
exports.updateOne = updateOne;
