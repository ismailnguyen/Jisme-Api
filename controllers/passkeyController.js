'use strict';
// Verified passkey enrollment (fresh password+MFA session), listing, deletion
// (password session + current password) and passkey-login options.
// POST users/login/passkey itself stays in userController.verifyPasskey.
const passkeyService = require('../services/passkeyService.js');
const policy = require('../services/sessionPolicy.js');
const { endpoint } = require('./securityEndpoint.js');

const fresh = (headers) => policy.passwordSession(headers, { fresh: true });
const passwordOnly = (headers) => policy.passwordSession(headers, { fresh: false });

exports.enrollmentOptions = endpoint({
    resolve: fresh,
    rateKind: 'sensitive',
    handler: async (session) => ({ status: 200, data: await passkeyService.registrationOptions(session.uuid, session.email) }),
});

exports.enroll = endpoint({
    resolve: fresh,
    rateKind: 'sensitive',
    handler: async (session, body, client) => ({ status: 201, data: await passkeyService.enroll(session.uuid, body, client || session.client) }),
});

exports.list = endpoint({
    resolve: policy.authenticated,
    rateKind: 'read',
    handler: async (session) => ({ status: 200, data: { passkeys: await passkeyService.list(session.uuid) } }),
});

exports.remove = endpoint({
    resolve: passwordOnly,
    rateKind: 'sensitive',
    handler: async (session, params, body, client) => ({
        status: 200,
        data: await passkeyService.remove(session.uuid, params && params.id, body, client || session.client),
    }),
});

// Pre-auth token from POST users/login binds the challenge to the user.
exports.loginOptions = endpoint({
    resolve: policy.preAuthenticated,
    rateKind: 'login',
    handler: async (session) => ({ status: 200, data: await passkeyService.authenticationOptions(session.uuid, 'authentication') }),
});
