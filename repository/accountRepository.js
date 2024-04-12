'use strict';

const { db_accounts_collection } = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const findOne = async function ({ query, fields }) {
    return await repository.findOne(db_accounts_collection,
    {
        filter: query,
        projection: fields
    });
}

const count = async function ({ query }) {
    return await repository.count(db_accounts_collection,
    {
        filter: query
    });
}

const findAll = async function ({ query, fields, max, offset, sortBy }) {
    return await repository.findAll(db_accounts_collection,
    {
        filter: query,
        projection: fields,
        limit: max,
        skip: offset,
        sort: sortBy
    });
}

const insertOne = async function (value) {
    return await repository.insertOne(db_accounts_collection, 
    {
        document: value
    });
}

const updateOne = async function ({ query, newValue }) {
    return await repository.updateOne(db_accounts_collection,
    {
        filter: query,
        update: newValue
    });
}

const deleteOne = async function ({ query }) {
    return await repository.deleteOne(db_accounts_collection,
    {
        filter: query
    });
}

exports.count = count;
exports.findOne = findOne;
exports.findAll = findAll;
exports.insertOne = insertOne;
exports.updateOne = updateOne;
exports.deleteOne = deleteOne;
