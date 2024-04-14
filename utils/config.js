'use strict';

if (process.env.NODE_ENV !== 'production') {
    const dotenv = require('dotenv');
    dotenv.config();
}

module.exports = {
    db_repository_type: process.env.DB_REPOSITORY_TYPE,

    db_uri: process.env.MONGODB_URI,
    db_name: process.env.MONGODB_DATABASE_NAME,

    db_api_action_base_url: process.env.DB_API_ACTION_BASE_URL,
    db_api_key: process.env.DB_API_KEY,

    db_data_source: process.env.DB_DATA_SOURCE,
    db_users_collection: process.env.DB_USERS_COLLECTION,
    db_accounts_collection: process.env.DB_ACCOUNTS_COLLECTION,
    
    port: process.env.PORT,

    token_master_secret: process.env.TOKEN_MASTER_SECRET,
    encryption_public_key_salt: process.env.ENCRYPTION_PUBLIC_KEY_SALT,
    encryption_private_key: process.env.ENCRYPTION_PRIVATE_KEY,
    encryption_private_iv: process.env.ENCRYPTION_PRIVATE_IV,
    hash_salt: process.env.HASH_SALT
}