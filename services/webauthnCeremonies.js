'use strict';
// Deliberately NOT mounted on HTTP. Caller must load credentials from trusted
// storage, persist enrollment/counter results and only then mint an auth session.
const {
    generateAuthenticationOptions,
    generateRegistrationOptions
} = require('@simplewebauthn/server');
const { createVerifier, assertNoPRF } = require('./webauthnVerifier.js');

exports.createCeremonies = function ({ config, challenges, verifySession, clock = Date.now }) {
    const verifier = createVerifier(config);

    async function freshSession(authorization) {
        // verifySession is a trusted server-side signature verifier, never request JSON.
        // auth_time represents completed authentication, not refresh/issue time.
        const session = typeof verifySession === 'function' ? await verifySession(authorization) : null;
        const age = clock() - (session?.auth_time * 1000);
        if (!session?.uuid || session.isAuthorized !== true || !Number.isSafeInteger(session.auth_time)
            || age < 0 || age >= 300000) {
            throw new Error('A fresh authenticated session is required for enrollment');
        }
        return session;
    }

    return {
        async registrationOptions(authorization, userName) {
            const session = await freshSession(authorization);
            const challenge = await challenges.issue(session.uuid, 'registration', clock());
            return generateRegistrationOptions({
                rpID: config.rpID,
                rpName: 'Jisme',
                userName,
                userID: Buffer.from(session.uuid),
                challenge: Buffer.from(challenge, 'base64url'),
                timeout: 300000,
                attestationType: 'none',
                supportedAlgorithmIDs: [-7],
                authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
            });
        },

        async registration(authorization, payload) {
            assertNoPRF(payload);
            const session = await freshSession(authorization);
            if (!await challenges.consume(payload.challenge, session.uuid, 'registration', clock())) {
                throw new Error('Invalid, expired or consumed challenge');
            }
            return verifier.registration({
                response: payload.response,
                challenge: payload.challenge,
                userId: session.uuid
            });
        },

        async authenticationOptions(userId, credentials) {
            const challenge = await challenges.issue(userId, 'authentication', clock());
            return generateAuthenticationOptions({
                rpID: config.rpID,
                challenge: Buffer.from(challenge, 'base64url'),
                userVerification: 'required',
                timeout: 300000,
                allowCredentials: credentials.filter(c => c.validated && c.userId === userId)
                    .map(c => ({ id: c.id }))
            });
        },

        async authentication(payload) {
            assertNoPRF(payload);
            const { challenge, userId } = payload;
            if (!await challenges.consume(challenge, userId, 'authentication', clock())) {
                throw new Error('Invalid, expired or consumed challenge');
            }
            return verifier.authentication(payload);
        }
    };
};
