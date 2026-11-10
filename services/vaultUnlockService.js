'use strict';
// Passkey (PRF) vault unlock.
//
// Protocol: the client runs an authentication ceremony for a vault-unlock
// challenge, requesting the PRF extension with its OWN locally-stored eval
// input. The authenticator's PRF output stays in the client, which uses it to
// unwrap the vault key inside the opaque envelope. The client strips
// clientExtensionResults.prf before posting the assertion; any PRF-named
// material reaching the server is refused (400). The server only learns that
// the user possesses a verified passkey and records per-user unlock state.
//
// Being authenticated (session token) is NOT being unlocked: unlock state
// only exists after this ceremony, expires after UNLOCK_TTL_MS and is cleared
// by lock, recovery and deletion of the passkey that produced it.
const { createHmac, randomBytes } = require('node:crypto');
const { sign, verify } = require('jsonwebtoken');
const { token_master_secret } = require('../utils/config.js');
const passkeys = require('./passkeyService.js');
const repository = require('../repository/vaultUnlockRepository.js');
const audit = require('./auditLog.js');
const { generateError } = require('../utils/errors.js');

const UNLOCK_TTL_MS = 300000;
const TOKEN_TYPE = 'vault_unlock';

// Domain-separated signing key: session tokens (master secret) cannot verify
// as unlock tokens and unlock tokens cannot verify as sessions.
const unlockKey = () => createHmac('sha256', String(token_master_secret || ''))
    .update('jisme.vault-unlock-token.v1').digest();

function assertConfigured() {
    if (!token_master_secret) throw generateError('Vault unlock unavailable', 'Try again later.', 503);
}

const options = async function (uuid) {
    return passkeys.authenticationOptions(uuid, 'vault-unlock');
};

const unlockWithPasskey = async function (uuid, body, client, now = Date.now()) {
    assertConfigured();
    const { credentialId } = await passkeys.authenticate(uuid, body, 'vault-unlock', client);
    const unlockId = randomBytes(16).toString('base64url');
    const expiresAt = now + UNLOCK_TTL_MS;
    try {
        await repository.set(uuid, { unlockId, method: 'passkey', credentialId, createdAt: now, expiresAt });
    } catch (_) {
        throw generateError('Vault unlock unavailable', 'Try again later.', 503);
    }
    const unlockToken = sign({ typ: TOKEN_TYPE, uid: uuid, jti: unlockId, amr: ['webauthn'] }, unlockKey(), {
        algorithm: 'HS256',
        expiresIn: Math.floor(UNLOCK_TTL_MS / 1000),
    });
    await audit.record(uuid, 'vault_unlocked', client);
    return { unlockToken, expiresAt: new Date(expiresAt).toISOString(), method: 'passkey' };
};

const isUnlocked = async function (uuid, now = Date.now()) {
    try {
        const state = await repository.find(uuid);
        return Boolean(state && Number.isSafeInteger(state.expiresAt) && state.expiresAt > now);
    } catch (_) {
        return false; // fail closed
    }
};

// True only for an unexpired unlock token of this user that matches the
// CURRENT server-side unlock state (lock/recovery revoke it immediately).
const verifyUnlockToken = async function (uuid, token, now = Date.now()) {
    try {
        if (!token_master_secret || typeof token !== 'string') return false;
        const claims = verify(token, unlockKey(), { algorithms: ['HS256'], clockTimestamp: Math.floor(now / 1000) });
        if (!claims || claims.typ !== TOKEN_TYPE || claims.uid !== uuid || typeof claims.jti !== 'string') return false;
        const state = await repository.find(uuid);
        return Boolean(state && state.unlockId === claims.jti && state.expiresAt > now);
    } catch (_) {
        return false;
    }
};

const lock = async function (uuid, client) {
    try {
        await repository.clear(uuid);
    } catch (_) {
        throw generateError('Vault unlock unavailable', 'Try again later.', 503);
    }
    await audit.record(uuid, 'vault_locked', client);
    return { locked: true };
};

exports.UNLOCK_TTL_MS = UNLOCK_TTL_MS;
exports.options = options;
exports.unlockWithPasskey = unlockWithPasskey;
exports.isUnlocked = isUnlocked;
exports.verifyUnlockToken = verifyUnlockToken;
exports.lock = lock;
