'use strict';
// Recovery codes. Issuing one needs any authenticated session (passkey sign-in
// included); using one (verify) needs a fresh password(+MFA) session.
// Recovery never restores vault contents (see services/recoveryService.js).
const recoveryService = require('../services/recoveryService.js');
const policy = require('../services/sessionPolicy.js');
const { endpoint } = require('./securityEndpoint.js');

const fresh = (headers) => policy.passwordSession(headers, { fresh: true });

// Fallback issuance for users whose first-run vault setup predates recovery
// codes (or whose issuance failed). 409 once a code exists.
exports.issue = endpoint({
    resolve: policy.authenticated,
    rateKind: 'sensitive',
    handler: async (session, _body, client) => ({ status: 201, data: await recoveryService.issue(session.uuid, client || session.client) }),
});

exports.verify = endpoint({
    resolve: fresh,
    rateKind: 'recovery',
    handler: async (session, body, client) => ({ status: 200, data: await recoveryService.verify(session.uuid, body, client || session.client) }),
});
