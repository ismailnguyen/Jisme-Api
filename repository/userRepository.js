const { db_users_collection } = require('../config.js');
const baseRepository = require('./baseRepository.js');

const findOne = async function ({ query, fields }) {
    return await baseRepository.findOne(db_users_collection,
    {
        filter: query,
        projection: fields
    });
}

const insertOne = async function (value) {
    return await baseRepository.insertOne(db_users_collection, 
    {
        document: value
    });
}

const updateOne = async function ({ query, newValue }) {
    return await baseRepository.updateOne(db_users_collection,
    {
        filter: query,
        update: newValue
    });
}

exports.findOne = findOne;
exports.insertOne = insertOne;
exports.updateOne = updateOne;
