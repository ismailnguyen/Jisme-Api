'use strict';
// Verified passkey enrollment and authentication (login + vault unlock).
//
// Invariants:
// - A credential is stored only after verifyRegistrationResponse succeeded
//   against a server-issued, single-use, user-bound challenge (TTL 2 min) with
//   the configured rpID/origin and user verification.
// - Authentication uses credentials from that trusted store, filtered by the
//   user the challenge was issued to, plus legacy users.passkeys entries whose
//   stored create() attestation yields a public key: those are verified with
//   the same signature check and promoted into the store on first success.
//   Anything else fails with the re-enrollment 403.
// - Sign counts must strictly increase (when the authenticator uses them) and
//   are advanced with a compare-and-set, so a cloned authenticator or a
//   concurrent replay is detected and refused.
// - PRF inputs/outputs never reach this module: callers reject them first and
//   the verifier rejects them again (assertNoPRF).
const {
    generateAuthenticationOptions,
    generateRegistrationOptions,
} = require('@simplewebauthn/server');
const { decodeAttestationObject, parseAuthenticatorData, isoBase64URL } = require('@simplewebauthn/server/helpers');
const { createHash } = require('node:crypto');
const { webauthn_rp_id, webauthn_origin } = require('../utils/config.js');
const { createVerifier } = require('./webauthnVerifier.js');
const challenges = require('../repository/webauthnChallengeRepository.js');
const credentials = require('../repository/webauthnCredentialRepository.js');
const { findOne: findUser, updateOne: updateUser } = require('../repository/userRepository.js');
const { encrypt, decrypt, hash } = require('../utils/cypher.js');
const { generateError } = require('../utils/errors.js');
const audit = require('./auditLog.js');

const CHALLENGE_TTL_MS = 120000;
const MAX_PASSKEYS_PER_USER = 10;
const MAX_NAME_LENGTH = 64;
const TRANSPORTS = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'];
const AUTH_PURPOSES = ['authentication', 'vault-unlock'];

const REENROLL_MESSAGE = 'Passkey re-enrollment required';
const REENROLL_REASON = 'Sign in with password (and MFA if enabled), then re-enroll your passkey via verified enrollment.';
const reenrollRequired = () => generateError(REENROLL_MESSAGE, REENROLL_REASON, 403);

let verifier = null;
const getVerifier = () => verifier || (verifier = createVerifier({ origin: webauthn_origin, rpID: webauthn_rp_id }));

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const userHandleOf = (uuid) => Buffer.from(uuid, 'utf8');

function ceremonyBody(body, code) {
    if (!isPlainObject(body) || typeof body.challenge !== 'string' || !isPlainObject(body.response)
        || typeof body.response.id !== 'string' || !body.response.id) {
        throw generateError('Invalid passkey input', 'Body must be {challenge, response}.', code);
    }
    return body;
}

// Storage failures never leak driver details.
async function storage(operation) {
    try {
        return await operation();
    } catch (_) {
        throw generateError('Passkey storage unavailable', 'Try again later.', 503);
    }
}

async function setPasskeyFlag(uuid) {
    const remaining = await storage(() => credentials.listByUser(uuid));
    // hasVerifiedPasskey only drives the login UX hint (requestLogin.hasPasskey).
    await storage(() => updateUser({ query: { uuid: encrypt(uuid) }, newValue: { hasVerifiedPasskey: remaining.length > 0 } }));
    return remaining.length;
}

function sanitizeTransports(response) {
    const supplied = response && response.response && response.response.transports;
    if (!Array.isArray(supplied)) return [];
    // Client order (a preference hint), allowlisted and de-duplicated.
    return supplied.filter((transport, index) => TRANSPORTS.includes(transport) && supplied.indexOf(transport) === index);
}

// Optional user-chosen label: trimmed string, max 64 chars; anything else is dropped.
function sanitizeName(name) {
    if (typeof name !== 'string') return undefined;
    const trimmed = name.trim().slice(0, MAX_NAME_LENGTH).trim();
    return trimmed || undefined;
}

const registrationOptions = async function (uuid, userName) {
    const existing = await storage(() => credentials.listByUser(uuid));
    const challenge = await storage(() => challenges.issue(uuid, 'registration', Date.now(), CHALLENGE_TTL_MS));
    return generateRegistrationOptions({
        rpID: webauthn_rp_id,
        rpName: 'Jisme',
        userName: typeof userName === 'string' && userName ? userName : uuid,
        userID: userHandleOf(uuid),
        challenge: Buffer.from(challenge, 'base64url'),
        timeout: CHALLENGE_TTL_MS,
        attestationType: 'none',
        supportedAlgorithmIDs: [-7],
        excludeCredentials: existing.map((c) => ({ id: c.credentialId, transports: c.transports })),
        // Local device only (platform attachment + 'client-device' hint): no
        // hybrid QR / external password-manager prompt on iOS.
        preferredAuthenticatorType: 'localDevice',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
};

const enroll = async function (uuid, body, client) {
    const { challenge, response } = ceremonyBody(body, 400);
    const existing = await storage(() => credentials.listByUser(uuid));
    if (existing.length >= MAX_PASSKEYS_PER_USER) {
        throw generateError('Passkey limit reached', `At most ${MAX_PASSKEYS_PER_USER} passkeys per user.`, 403);
    }
    if (!await storage(() => challenges.consume(challenge, uuid, 'registration', Date.now()))) {
        throw generateError('Invalid passkey challenge', 'Invalid, expired or consumed challenge; request new options.', 400);
    }
    let verified;
    try {
        verified = await getVerifier().registration({ response, challenge, userId: uuid });
    } catch (_) {
        throw generateError('Passkey verification failed', 'The registration response could not be verified.', 400);
    }
    const createdAt = new Date().toISOString();
    const transports = sanitizeTransports(response);
    const name = sanitizeName(body.name);
    const inserted = await storage(() => credentials.insert(uuid, {
        credentialId: verified.id,
        publicKey: verified.publicKey,
        counter: verified.counter,
        transports,
        createdAt,
        name,
    }));
    if (!inserted) {
        throw generateError('Passkey already registered', 'This passkey is already enrolled.', 409);
    }
    await setPasskeyFlag(uuid);
    await audit.record(uuid, 'passkey_enrolled', client);
    return { id: verified.id, transports, createdAt, ...(name ? { name } : {}) };
};

// Keep IDs aligned with the client normalization for old user documents.
const legacyId = (entry) => entry.id ?? entry.credentialId ?? entry.passkey?.id;

// The previous client enrolled without rp.id, so its credentials are scoped to
// the exact host it ran on; the configured rpID may be a parent domain.
const LEGACY_RP_IDS = [...new Set([webauthn_rp_id, new URL(webauthn_origin).hostname])];
const rpIdOfHash = (rpIdHash) => LEGACY_RP_IDS.find((rp) => createHash('sha256').update(rp).digest().equals(Buffer.from(rpIdHash)));

// Legacy users.passkeys entries hold the full create() response. Its
// attestationObject carries the public key, so the passkey can be verified
// cryptographically without re-enrollment. userHandle: the old client passed the
// uuid string where webauthn-json expected base64url, so authenticators echo it back
// as that same string. Entries that cannot be decoded stay legacy (verified: false).
function decodeLegacyPasskey(uuid, entry) {
    try {
        const id = legacyId(entry);
        const attestation = entry.passkey?.response?.attestationObject;
        if (typeof id !== 'string' || typeof attestation !== 'string') return null;
        const authData = parseAuthenticatorData(decodeAttestationObject(isoBase64URL.toBuffer(attestation)).get('authData'));
        const rpId = rpIdOfHash(authData.rpIdHash);
        if (!rpId || !authData.credentialID || !authData.credentialPublicKey
            || isoBase64URL.fromBuffer(authData.credentialID) !== id) return null;
        return {
            credentialId: id,
            publicKey: isoBase64URL.fromBuffer(authData.credentialPublicKey),
            counter: authData.counter,
            transports: sanitizeTransports(entry.passkey),
            name: sanitizeName(entry.deviceName),
            rpId,
            userHandle: uuid,
            legacy: true,
            promote: true, // not yet in the credential store
            validated: true,
        };
    } catch (_) {
        return null;
    }
}

const decodeLegacyPasskeys = (user) => (Array.isArray(user?.passkeys) ? user.passkeys : [])
    .filter(isPlainObject)
    .map((entry) => decodeLegacyPasskey(decrypt(user.uuid), entry))
    .filter(Boolean);

// Store credentials first, then legacy ones not yet promoted.
async function usableCredentials(uuid) {
    const items = await storage(() => credentials.listByUser(uuid));
    const user = await storage(() => findUser({ query: { uuid: encrypt(uuid) } }));
    const legacy = decodeLegacyPasskeys(user).filter((l) => !items.some((c) => c.credentialId === l.credentialId));
    return [...items, ...legacy];
}

const list = async function (uuid) {
    const items = await storage(() => credentials.listByUser(uuid));
    const user = await storage(() => findUser({ query: { uuid: encrypt(uuid) } }));
    const legacy = Array.isArray(user?.passkeys) ? user.passkeys : [];
    return [...items.map((c) => ({
        id: c.credentialId,
        transports: c.transports || [],
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt || null,
        ...(typeof c.name === 'string' && c.name ? { name: c.name } : {}),
        verified: true,
    })), ...legacy.filter((p) => isPlainObject(p) && typeof legacyId(p) === 'string'
        && !items.some((c) => c.credentialId === legacyId(p))).map((p) => ({
        id: legacyId(p),
        deviceName: p.deviceName,
        verified: false,
    }))];
};

// Requires the CURRENT password even inside a password session.
const remove = async function (uuid, credentialId, body, client) {
    const password = isPlainObject(body) ? body.password : undefined;
    if (typeof password !== 'string' || !password) {
        throw generateError('Invalid user input', 'Current password is required.', 400);
    }
    if (typeof credentialId !== 'string' || !/^[A-Za-z0-9_-]{1,1366}$/.test(credentialId)) {
        throw generateError('Invalid user input', 'Invalid passkey id.', 400);
    }
    const confirmed = await storage(() => findUser({ query: { uuid: encrypt(uuid), password: encrypt(hash(password)) } }));
    if (!confirmed) {
        await audit.record(uuid, 'passkey_delete_failed', client);
        throw generateError('Unauthorized', 'Password confirmation failed.', 401);
    }
    const removed = await storage(() => credentials.remove(uuid, credentialId));
    if (!removed) {
        const legacy = Array.isArray(confirmed.passkeys) ? confirmed.passkeys : [];
        const matches = (entry) => isPlainObject(entry) && legacyId(entry) === credentialId;
        if (!legacy.some(matches)) {
            throw generateError('Not found', 'Passkey not found.', 404);
        }
        const updated = await storage(() => updateUser({
            query: { uuid: encrypt(uuid) },
            newValue: { passkeys: legacy.filter((entry) => !matches(entry)) },
        }));
        if (!updated) throw generateError('Not found', 'Passkey not found.', 404);
        await audit.record(uuid, 'passkey_deleted', client);
        return { id: credentialId, removed: true, legacy: true };
    }
    await setPasskeyFlag(uuid);
    // An unlock obtained with this passkey does not outlive it.
    try {
        const unlock = require('../repository/vaultUnlockRepository.js');
        const state = await unlock.find(uuid);
        if (state && state.credentialId === credentialId) await unlock.clear(uuid);
    } catch (_) {
        // unlock state expires on its own (short TTL)
    }
    await audit.record(uuid, 'passkey_deleted', client);
    return { id: credentialId, deleted: true };
};

const authenticationOptions = async function (uuid, purpose) {
    if (!AUTH_PURPOSES.includes(purpose)) throw generateError('Invalid passkey input', 'Unknown ceremony.', 400);
    const items = await usableCredentials(uuid);
    const challenge = await storage(() => challenges.issue(uuid, purpose, Date.now(), CHALLENGE_TTL_MS));
    // Legacy credentials live under the host they were enrolled on; when every
    // usable credential shares that other rpID, the ceremony must use it.
    const rpIDs = new Set(items.map((c) => c.rpId || webauthn_rp_id));
    const rpID = rpIDs.size === 1 && !rpIDs.has(webauthn_rp_id) ? [...rpIDs][0] : webauthn_rp_id;
    // No `extensions` here: for vault unlock the client adds its own PRF eval
    // input locally and strips clientExtensionResults.prf before posting.
    return generateAuthenticationOptions({
        rpID,
        challenge: Buffer.from(challenge, 'base64url'),
        // Legacy passkeys were enrolled with 'preferred'; keep them usable.
        userVerification: items.some((c) => c.legacy) ? 'preferred' : 'required',
        timeout: CHALLENGE_TTL_MS,
        // Transports as stored: the browser decides (platform, USB key, QR/hybrid).
        allowCredentials: items.map((c) => ({ id: c.credentialId, ...(c.transports?.length ? { transports: c.transports } : {}) })),
    });
};

// Verifies an assertion for `uuid` and `purpose`. Returns the credential id.
const authenticate = async function (uuid, body, purpose, client) {
    if (!AUTH_PURPOSES.includes(purpose)) throw generateError('Invalid passkey input', 'Unknown ceremony.', 400);
    const { challenge, response } = ceremonyBody(body, 400);
    if (!await storage(() => challenges.consume(challenge, uuid, purpose, Date.now()))) {
        throw generateError('Unauthorized', 'Invalid, expired or consumed challenge; request new options.', 401);
    }
    const stored = await storage(() => credentials.findForUser(uuid, response.id))
        || (await usableCredentials(uuid)).find((c) => c.promote && c.credentialId === response.id);
    if (!stored) {
        // Unknown here = undecodable legacy passkey, removed passkey or another
        // user's credential: all must re-enroll through verification.
        await audit.record(uuid, 'passkey_auth_failed', client);
        throw reenrollRequired();
    }
    let info;
    try {
        info = await getVerifier().authentication({
            response,
            challenge,
            userId: uuid,
            credential: {
                id: stored.credentialId, publicKey: stored.publicKey, counter: stored.counter, userId: uuid,
                validated: stored.validated === true, legacy: stored.legacy === true, rpId: stored.rpId, userHandle: stored.userHandle,
            },
        });
    } catch (error) {
        const cloned = /counter/i.test(error && error.message);
        await audit.record(uuid, cloned ? 'passkey_clone_suspected' : 'passkey_auth_failed', client);
        throw generateError('Unauthorized', cloned
            ? 'Passkey sign count did not increase; this authenticator may be cloned.'
            : 'Passkey verification failed.', 401);
    }
    if (stored.promote) {
        // First verified use of a legacy passkey: promote it into the store (the
        // users.passkeys entry is left as is). A concurrent promotion loses the
        // exclusive insert and is refused like any counter race.
        const inserted = await storage(() => credentials.insert(uuid, {
            credentialId: stored.credentialId, publicKey: stored.publicKey, counter: info.newCounter,
            transports: stored.transports, createdAt: new Date().toISOString(), name: stored.name,
            rpId: stored.rpId, userHandle: stored.userHandle, legacy: true,
        }));
        if (!inserted) {
            await audit.record(uuid, 'passkey_clone_suspected', client);
            throw generateError('Unauthorized', 'Concurrent use of this passkey was detected; try again.', 401);
        }
        await setPasskeyFlag(uuid);
        await audit.record(uuid, 'passkey_migrated', client);
        return { credentialId: stored.credentialId };
    }
    const advanced = await storage(() => credentials.compareAndSetCounter(uuid, stored.credentialId, stored.counter, {
        counter: info.newCounter,
        lastUsedAt: new Date().toISOString(),
    }));
    if (!advanced) {
        await audit.record(uuid, 'passkey_clone_suspected', client);
        throw generateError('Unauthorized', 'Concurrent use of this passkey was detected; try again.', 401);
    }
    return { credentialId: stored.credentialId };
};

exports.CHALLENGE_TTL_MS = CHALLENGE_TTL_MS;
exports.MAX_PASSKEYS_PER_USER = MAX_PASSKEYS_PER_USER;
exports.REENROLL_MESSAGE = REENROLL_MESSAGE;
exports.REENROLL_REASON = REENROLL_REASON;
exports.decodeLegacyPasskeys = decodeLegacyPasskeys;
exports.registrationOptions = registrationOptions;
exports.enroll = enroll;
exports.list = list;
exports.remove = remove;
exports.authenticationOptions = authenticationOptions;
exports.authenticate = authenticate;
