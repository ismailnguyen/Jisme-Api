// const db = require('./dbConnector.js');
const api = require('./apiConnector.js');

const findOne = async function (collection, { filter, projection }) {
    const response = await api.sendQuery(collection,
	{
        action: 'findOne',
        filter: filter,
        projection: projection
    });

    if (!response || !response.data || !response.data.document) {
        return null;
    }

    return response.data.document;
}

const findAll = async function (collection, { filter, projection, limit }) {
    const response = await api.sendQuery(collection,
	{
        action: 'find',
        filter: filter,
        projection: projection,
        limit: limit
    });

    if (!response || !response.data || !response.data.documents) {
        return [];
    }

    return response.data.documents;
}

const insertOne = async function (collection, { document }) {
    const response = await api.sendQuery(collection,
	{
        action: 'insertOne',
        document: document
    });

    let insertedData = document;
    // Give back the id of inserted content
    // Because the insert query doesn't give back the id
    insertedData._id = response.data.insertedId;

    return insertedData;
}

const updateOne = async function (collection, { filter, update }) {
    const updateId = filter._id; // Store it before it's changed into ObjectId

    await api.sendQuery(collection,
	{
        action: 'updateOne',
        filter: filter,
        update: update
    });

    let updatedData = update;
    // Give back the id of updated content
    // Because the update query doesn't give back the id
    updatedData._id = updateId;

    return updatedData;
}

const deleteOne = async function (collection, { filter }) {
    const deletedData = await api.sendQuery(collection,
    {
        action: 'deleteOne',
        filter: filter
    });

    return deletedData;
}

exports.findOne = findOne;
exports.findAll = findAll;
exports.updateOne = updateOne;
exports.insertOne = insertOne;
exports.deleteOne = deleteOne;
