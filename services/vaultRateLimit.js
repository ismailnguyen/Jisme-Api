'use strict';
// In-memory, per-owner fixed-window rate limiter for the vault endpoints.
// Shared by the Express server and the Netlify function through the controller.
//
// Fail closed: there is no configuration, environment variable or runtime path
// that can disable the limiter or widen its budgets, and any internal fault
// denies the request instead of allowing it.
//
// Documented limitation: the state is per-process. On a serverless cold start
// the current window is lost and starts empty; the limiter bounds request
// storms against a warm instance and never weakens any other security check.
// Nothing here is a security boundary against a determined distributed
// attacker — it is an abuse bound for quota-churn and read-storm patterns.

const LIMITS = Object.freeze({
    WINDOW_MS: 60000,
    // Reads: one vault sync (list + a few gets) fits easily; sustained ~1/s.
    READS_PER_WINDOW: 60,
    // Writes: far above a human edit/merge/delete loop, far below the churn
    // rate needed to burn the 64-name tombstone quota or hammer CAS retries.
    WRITES_PER_WINDOW: 20,
    MAX_TRACKED_KEYS: 200000, // memory bound for abandoned owners
});

const buckets = new Map(); // `${owner}\x00${kind}` -> { count, resetAt }

function deny(retryAfterSeconds) {
    return { allowed: false, retryAfterSeconds };
}

function limitFor(kind) {
    if (kind === 'read') return LIMITS.READS_PER_WINDOW;
    if (kind === 'write') return LIMITS.WRITES_PER_WINDOW;
    return 0; // unknown kind: nothing is allowed (fail closed)
}

// Counts one request against the owner's per-kind window. Pure and synchronous
// so the caller can reject before any storage or validation work happens.
function consume(owner, kind, now = Date.now()) {
    try {
        if (typeof owner !== 'string' || owner === '' || typeof now !== 'number' || !Number.isFinite(now)) {
            return deny(60);
        }
        const limit = limitFor(kind);
        if (limit < 1) return deny(60);
        const resetAt = Math.floor(now / LIMITS.WINDOW_MS) * LIMITS.WINDOW_MS + LIMITS.WINDOW_MS;
        const key = owner + '\0' + kind;
        let bucket = buckets.get(key);
        if (!bucket || bucket.resetAt !== resetAt) {
            if (buckets.size >= LIMITS.MAX_TRACKED_KEYS) buckets.clear(); // counters only
            bucket = { count: 0, resetAt };
            buckets.set(key, bucket);
        }
        bucket.count += 1;
        if (bucket.count > limit) {
            return deny(Math.min(60, Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
        }
        return { allowed: true, retryAfterSeconds: 0 };
    } catch (_) {
        return deny(60); // internal fault: fail closed, never open
    }
}

exports.LIMITS = LIMITS;
exports.consume = consume;
