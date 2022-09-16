const {
    db_uri,
    db_name
} = require('../config.js');
const MongoClient = require('mongodb').MongoClient;
var ObjectId = require('mongodb').ObjectId;

const getDbConnection = async function () {
	const client = await MongoClient.connect(db_uri, {useNewUrlParser: true, useUnifiedTopology: true});

    return client.db(db_name);
}

const sendQuery = async function (collection, { action, filter, projection, limit, document, update }) {
    const connection = await getDbConnection();
    const db = connection.collection(collection);

    if (filter && filter._id) {
        filter._id = new ObjectId(filter._id);
    }

    if (document && document._id) {
        delete document._id;
    }

    if (update && update._id) {
        delete update._id;
    }

    if (action == 'findOne') {
        return {
            data: {
                document: db.findOne(filter)
            }
        };
    }

    if (action == 'find') {
        return {
            data: {
                documents: db.find(filter).toArray()
            }
        };
    }

    if (action == 'insertOne') {
        const response = db.insertOne(document);
        return {
            data: {
                insertedId: response.ops[0]._id
            }
        };
    }

    if (action == 'updateOne') {
        return db.updateOne(filter, { $set: update });
    }

    if (action == 'deleteOne') {
        return db.deleteOne(filter);
    }
}

exports.sendQuery = sendQuery;
