if (process.env.NODE_ENV !== 'production') {
    const dotenv = require('dotenv');
    dotenv.config();
}

module.exports = {
    db_uri: process.env.MONGODB_URI,
    db_name: process.env.MONGODB_DATABASE_NAME,
    port: process.env.PORT
}