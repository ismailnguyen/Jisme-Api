'use strict';
// Standalone building block; legacy HTTP passkey login remains disabled.
const {
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} = require('@simplewebauthn/server');

function assertNoPRF(value) {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
        if (/prf/i.test(key)) {
            throw new Error('PRF inputs/outputs are local vault-unlock material and must not be sent to the server');
        }
        assertNoPRF(child);
    }
}

function decode(value) {
    if (typeof value !== 'string' || !value || !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new Error('Expected canonical base64url');
    }
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value) {
        throw new Error('Expected canonical base64url');
    }
    return decoded;
}

function checkResponse(response) {
    assertNoPRF(response);
    const client = JSON.parse(decode(response?.response?.clientDataJSON).toString('utf8'));
    if (client.crossOrigin || client.topOrigin) {
        throw new Error('Cross-origin ceremonies are not supported');
    }
}

function createVerifier({ origin, rpID }) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password
        || typeof rpID !== 'string' || !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(rpID)
        || !(url.hostname === rpID || url.hostname.endsWith('.' + rpID))) {
        throw new Error('Explicit HTTPS origin and matching DNS rpID required');
    }

    return {
        async authentication({ response, challenge, credential, userId }) {
            checkResponse(response);
            decode(challenge);
            // credential must be loaded from trusted server storage, never request JSON.
            if (!userId || credential?.validated !== true || credential.userId !== userId
                || credential.id !== response.id || !Number.isSafeInteger(credential.counter)
                || credential.counter < 0) {
                throw new Error('Unverified legacy credential or wrong user; sign in with password and re-enroll');
            }
            if (response.response.userHandle != null
                && response.response.userHandle !== Buffer.from(userId).toString('base64url')) {
                throw new Error('Wrong userHandle');
            }
            const result = await verifyAuthenticationResponse({
                response,
                expectedChallenge: challenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: true,
                credential: {
                    id: credential.id,
                    publicKey: new Uint8Array(decode(credential.publicKey)),
                    counter: credential.counter
                }
            });
            if (!result.verified) throw new Error('Invalid signature');
            return result.authenticationInfo;
        },

        async registration({ response, challenge, userId }) {
            checkResponse(response);
            decode(challenge);
            if (!userId) throw new Error('User required');
            const result = await verifyRegistrationResponse({
                response,
                expectedChallenge: challenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: true,
                requireUserPresence: true,
                supportedAlgorithmIDs: [-7]
            });
            if (!result.verified || result.registrationInfo.credential.id !== response.id) {
                throw new Error('Invalid registration');
            }
            const credential = result.registrationInfo.credential;
            return {
                id: credential.id,
                publicKey: Buffer.from(credential.publicKey).toString('base64url'),
                counter: credential.counter,
                userId,
                validated: true
            };
        }
    };
}

exports.createVerifier = createVerifier;
exports.assertNoPRF = assertNoPRF;
