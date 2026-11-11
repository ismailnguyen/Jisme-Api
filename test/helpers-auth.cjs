'use strict';
// Shared bootstrap for the passkey / unlock / recovery suites: synthetic env,
// in-memory mock store, seeded users and trusted-session token builders.
// Must be required BEFORE any application module.
const { config } = require('./fixtures.cjs');

global.__JISME_MOCK_STORE__ = { users: [], accounts: [], activities: [], webauthnChallenges: [], vaultEnvelopes: [] };
Object.assign(process.env, {
    NODE_ENV: 'test',
    DB_REPOSITORY_TYPE: 'mock',
    TOKEN_MASTER_SECRET: 'unit-test-token-secret',
    ENCRYPTION_PRIVATE_KEY: '0123456789abcdef0123456789abcdef',
    ENCRYPTION_PRIVATE_IV: 'abcdef0123456789',
    HASH_SALT: 'unit-test-salt',
    DB_USERS_COLLECTION: 'users',
    DB_USERS_ACTIVITY_LOG_COLLECTION: 'users_activity_log',
    DB_ACCOUNTS_COLLECTION: 'accounts',
    LOGIN_DELAY_IN_SECONDS: '300',
    WEBAUTHN_RP_ID: config.rpID,
    WEBAUTHN_ORIGIN: config.origin,
});
// No network from tests: login() geolocates the client IP.
require('../utils/location.js').findLocationFromIp = async () => null;

const { sign } = require('jsonwebtoken');
const { encrypt, decrypt, hash } = require('../utils/cypher.js');

const store = () => global.__JISME_MOCK_STORE__;
const nowS = () => Math.floor(Date.now() / 1000);
const email = (uuid) => `${uuid}@example.invalid`;
const bearer = (claims, secret = 'unit-test-token-secret') => ({ authorization: 'Bearer ' + sign(claims, secret, { expiresIn: '1h' }) });

// Fully authenticated session. amr records HOW the user authenticated.
const strong = (uuid, { amr = ['pwd'], authTime = nowS() } = {}) => bearer({
    uuid, email: email(uuid), step: 'loggedIn', isAuthorized: true, auth_time: authTime, amr,
});
// Pre-auth token as issued by POST users/login.
const preAuth = (uuid) => bearer({ uuid, email: email(uuid), step: 'request_password', isAuthorized: false });

function seedUser(uuid, { password = 'correct horse battery', mfa = false, legacyPasskeys } = {}) {
    const user = {
        _id: 'id-' + uuid,
        uuid: encrypt(uuid),
        email: encrypt(email(uuid)),
        password: encrypt(hash(password)),
        isMFAEnabled: mfa,
        totp_secret: encrypt('JBSWY3DPEHPK3PXP'),
        public_encryption_key: encrypt('pk'),
        token: encrypt('t'),
        created_date: '2026-01-01T00:00:00.000Z',
    };
    if (legacyPasskeys) user.passkeys = legacyPasskeys;
    store().users.push(user);
    return user;
}

const userDoc = (uuid) => store().users.find((u) => u.uuid === encrypt(uuid));
const auditActions = (uuid) => store().activities.filter((a) => a.uuid === encrypt(uuid)).map((a) => decrypt(a.action));
const credentials = () => (store().webauthnCredentials || []);
const challengeOf = (options) => options.challenge;
const decodeJwt = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const client = { agent: 'unit-agent', referer: 'unit', ip: '127.0.0.1' };

module.exports = {
    store, nowS, email, bearer, strong, preAuth, seedUser, userDoc, auditActions,
    credentials, challengeOf, decodeJwt, client, encrypt, decrypt,
};
