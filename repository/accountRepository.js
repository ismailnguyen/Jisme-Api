'use strict';

const {
    db_accounts_collection: collection
} = require('../utils/config.js');
const repository = require('./ports/repositoryPort.js');

const findOne = async function ({ query, fields }) {
    return await repository.findOne(collection, {
        filter: query,
        projection: fields
    });
}

const count = async function ({ query }) {
    return await repository.count(collection, {
        filter: query
    });
}

const findAll = async function ({ query, fields, max, offset, sortBy }) {
    return await repository.findAll(collection, {
        filter: query,
        projection: fields,
        limit: max,
        skip: offset,
        sort: sortBy
    });
}

const insertOne = async function (value) {
    return await repository.insertOne(collection, {
        document: value
    });
}

const insertMultiple = async function (values) {
    return await repository.insertMultiple(collection, {
        documents: values
    });
}

const updateOne = async function ({ query, newValue }) {
    return await repository.updateOne(collection, {
        filter: query,
        update: newValue
    });
}

const deleteOne = async function ({ query }) {
    return await repository.deleteOne(collection, {
        filter: query
    });
}

exports.count = count;
exports.findOne = findOne;
exports.findAll = findAll;
exports.insertOne = insertOne;
exports.insertMultiple = insertMultiple;
exports.updateOne = updateOne;
exports.deleteOne = deleteOne;
