
const {
    db_uri,
    db_name
} = require('../../utils/config.js');

const {
    MongoClient,
    ServerApiVersion
} = require('mongodb');

const connection = function () {
    var db = null;
    var instance = 0;

    async function connect () {
        try {
            const client = await new MongoClient(db_uri, {
                serverApi: ServerApiVersion.v1
            });
        
            return client.db(db_name);
        } catch (error) {
            console.log(error);
        }
    }

    async function getInstance () {
        try {
            // increment the number of singleton instances
            instance++;

            if (!db) {
                db = await connect();
            }

            return db;
        } catch (error) {
            console.log(error);
        }
    }
    
	return {
        getInstance
    };
}

module.exports = connection();
