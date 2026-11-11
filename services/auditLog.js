'use strict';
// Security audit entries in the existing users_activity_log collection, in the
// same encrypted shape as login activities (visible to the user in GET /users).
const { insertOne: logActivity } = require('../repository/userActivitiesRepository.js');
const { encrypt } = require('../utils/cypher.js');

const ACTIONS = Object.freeze([
    'passkey_enrolled', 'passkey_deleted', 'passkey_delete_failed', 'passkey_auth_failed',
    'passkey_clone_suspected', 'passkey_migrated', 'vault_unlocked', 'vault_locked',
    'recovery_code_issued', 'recovery_code_rotated', 'recovery_used', 'recovery_failed',
]);

// Best effort by design: an audit-store outage must not turn into an auth
// bypass or a lock-out, so failures are reported to the server log only.
// Never pass secrets (codes, keys, assertions) in here.
exports.record = async function (uuid, action, client = {}) {
    if (!ACTIONS.includes(action) || typeof uuid !== 'string' || !uuid) return false;
    try {
        await logActivity({
            uuid: encrypt(uuid),
            action: encrypt(action),
            agent: encrypt(client && client.agent),
            referer: encrypt(client && client.referer),
            ip: encrypt(client && client.ip),
            activity_date: new Date().toISOString(),
            location: '',
        });
        return true;
    } catch (error) {
        console.error('AUDIT: failed to record ' + action);
        return false;
    }
};

exports.ACTIONS = ACTIONS;
