# Behaviour contract — Jisme-Api

What must not change, from the user's point of view. Every line is covered by
a named test; a task that would require breaking a line stops and raises the
question to the human. Editing this file is a human decision.

## Sign-in

1. An account with a passkey enrolled by a previous version (`users.passkeys`)
   is routed to the passkey as soon as the email is entered, and that passkey
   signs in without re-enrollment. — `test/legacy-passkey.test.cjs`
2. A passkey assertion is verified by signature against a public key stored on
   the server. An identifier alone never signs in. —
   `test/passkey-login.test.cjs`, `test/legacy-passkey.test.cjs`
3. An account with a verified passkey goes straight to the passkey ceremony;
   every other account keeps the password step. — `test/login-passkey-first.test.cjs`
4. Password sign-in keeps the `LOGIN_DELAY_IN_SECONDS` cooldown and is not
   subject to the in-memory rate limit. — `test/password-login-cooldown.test.cjs`
5. A passkey's transports are returned as stored; the server never forces
   `internal`. — `test/passkey-ceremony-options.test.cjs`

## Sessions

6. A token issued before `auth_time`/`amr` existed is still an authenticated
   session; only enrollment requires a fresh sign-in. —
   `test/legacy-passkey.test.cjs`
7. PUT /users ignores the `passkeys` field instead of rejecting the request. —
   `test/passkey-enrollment.test.cjs`

## Recovery

8. Generating a recovery code works from any authenticated session, passkey
   sign-in included, and replaces the existing code. — `test/recovery.test.cjs`
9. Using a code (verify), enrolling or deleting a passkey require a password
   session (+ MFA when enabled). — `test/recovery.test.cjs`,
   `test/passkey-enrollment.test.cjs`

## Configuration

10. `WEBAUTHN_RP_ID` defaults to the hostname of `WEBAUTHN_ORIGIN`;
    `http://localhost` is accepted outside production. —
    `test/passkey-enrollment.test.cjs`, `test/webauthn.test.cjs`
