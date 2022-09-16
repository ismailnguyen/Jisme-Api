if (process.env.NODE_ENV !== 'production') {
    const dotenv = require('dotenv');
    dotenv.config();
}

module.exports = {
    db_uri: process.env.MONGODB_URI,
    db_name: process.env.MONGODB_DATABASE_NAME,
    db_data_source: process.env.DB_DATA_SOURCE,
    db_users_collection: process.env.DB_USERS_COLLECTION,
    db_accounts_collection: process.env.DB_ACCOUNTS_COLLECTION,
    db_api_action_base_url: process.env.DB_API_ACTION_BASE_URL,
    db_api_key: process.env.DB_API_KEY,
    port: process.env.PORT,
    token_master_secret: process.env.TOKEN_MASTER_SECRET
}