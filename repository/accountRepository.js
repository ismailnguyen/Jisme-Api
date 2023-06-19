const { db_accounts_collection } = require('../config.js');
const baseRepository = require('./baseRepository.js');

const findOne = async function ({ query, fields }) {
    return await baseRepository.findOne(db_accounts_collection,
    {
        filter: query,
        projection: fields
    });
}

const findAll = async function ({ query, fields, max }) {
    return await baseRepository.findAll(db_accounts_collection,
    {
        filter: query,
        projection: fields,
        limit: max
    });
}

const insertOne = async function (value) {
    return await baseRepository.insertOne(db_accounts_collection, 
    {
        document: value
    });
}

const updateOne = async function ({ query, newValue }) {
    return await baseRepository.updateOne(db_accounts_collection,
    {
        filter: query,
        update: newValue
    });
}

const deleteOne = async function ({ query }) {
    return await baseRepository.deleteOne(db_accounts_collection,
    {
        filter: query
    });
}

exports.findOne = findOne;
exports.findAll = findAll;
exports.insertOne = insertOne;
exports.updateOne = updateOne;
exports.deleteOne = deleteOne;