# Verified passkeys, PRF vault unlock and recovery (P1)

## Sessions

Signed session tokens carry `amr` (`pwd`, `otp`, `webauthn`) next to `auth_time`.

| requirement | meaning |
|---|---|
| pre-auth | any valid token with a uuid (from `POST users/login`) |
| authenticated | `isAuthorized` and an integer `auth_time` |
| password session | authenticated, `amr` has `pwd` (and `otp` when MFA is enabled) |
| fresh | `auth_time` within the last 5 minutes |

Passkey-only sessions (`amr: ["webauthn"]`) cannot manage passkeys or use recovery.

## Endpoints

| endpoint | session | rate-limit bucket |
|---|---|---|
| `POST users/passkeys/options` | fresh password | sensitive (20/min) |
| `POST users/passkeys` `{challenge, response}` | fresh password | sensitive |
| `GET users/passkeys` | authenticated | read |
| `DELETE users/passkeys/:id` `{password}` | password session + current password | sensitive |
| `POST users/login/passkey/options` | pre-auth | login (20/min) |
| `POST users/login/passkey` `{challenge, response, isExtendedSession}` | pre-auth | login |
| `POST vaults/unlock/passkey/options` | authenticated | sensitive |
| `POST vaults/unlock/passkey` `{challenge, response}` | authenticated | sensitive |
| `POST vaults/lock` | authenticated | write |
| `POST users/recovery` | fresh password | sensitive |
| `POST users/recovery/verify` `{recoveryCode, action}` | fresh password | recovery (5/min) |

- Challenges are stored on the server. They last 2 minutes, can be used once, and are bound to the user and to a purpose (`registration`, `authentication` or `vault-unlock`).
- WebAuthn settings come from `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN`. When unset, they default to `jisme.app` and `https://www.jisme.app`.
- Credentials are stored in `webauthn_credentials` only after `verifyRegistrationResponse` succeeds. Each record holds the credential id, the validated public key, the counter and the transports. The stored owner is a hash of the user's uuid.
- On login and unlock, the server runs `verifyAuthenticationResponse` with the expected rpID and origin, and requires user verification. The sign count must go up when the authenticator uses one. The new counter is saved with a compare-and-set, so a cloned authenticator or a replayed assertion is refused and audited.
- Legacy passkeys in `users.passkeys` were never verified. They are never used, and login with one still returns `403 Passkey re-enrollment required`. `PUT /users` with `passkeys` is still refused with 403.

## PRF material never reaches the server

The server never sends PRF salts. To unlock with a passkey, the client:

1. adds `extensions.prf.eval` itself, using its own locally stored input;
2. uses the PRF output locally to unwrap the vault key inside the envelope;
3. **removes `clientExtensionResults.prf` before it sends the assertion.**

Any key matching `/prf/i` in any input of any new endpoint is refused with 400. The same applies during enrollment: remove `clientExtensionResults.prf` (including `{enabled: true}`).

A successful unlock returns `{unlockToken, expiresAt, method}`:

- The token lasts 5 minutes. It is signed with a key separate from the session key, so a session token is never an unlock token and an unlock token is never a session token.
- It is valid only while it matches the user's current record in `vault_unlock_state`.
- Logging in does not unlock the vault. The unlock record is cleared by `POST vaults/lock`, by recovery, and by deleting the passkey that performed the unlock.

## Recovery

- The first vault create (`PUT /vaults/:id` with `expectedRevision: 0`) returns `recoveryCode` once, when the user has no code yet. `POST users/recovery` is the fallback for users who have no code; it returns 409 if a code already exists.
- A code is 160 random bits, shown as 8 groups of Crockford base32. The server stores only a scrypt hash with a random salt for each record (`recovery_codes`).
- `POST users/recovery/verify` accepts two actions:
  - `reset_unlock` clears the unlock state;
  - `reenroll_passkeys` also revokes every verified passkey.
- A code works once. A successful verify swaps in a new code with a compare-and-set and returns that new code once.
- Every attempt is rate limited and audited in `users_activity_log`.

**Invariant: recovery cannot restore vault contents.** Vault data is encrypted on the client with keys that come from the user's unlock secret. The recovery code is not one of those keys, and the server holds none of them. If every unlock secret is lost, the ciphertext cannot be recovered. Recovery only lets the user take back control of the account, set a new unlock secret (which means a new vault) and enroll new passkeys.

## Known limits

- Rate limits are kept in memory for each process, like the vault limiter, so a serverless cold start resets them. Recovery codes are 160 bits, so this does not make guessing a code feasible.
- Audit entries are written on a best-effort basis: a failure is logged on the server and does not block the request. `login()` keeps only the 10 most recent activity rows, and that includes audit rows.
- Vault envelope CRUD still only requires a session, because envelopes are encrypted on the client. The unlock token is ready for gating vault access when clients adopt it.
