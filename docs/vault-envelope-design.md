# Client vault envelope storage — design (P1, option A)

Status: implemented for vault envelope CRUD. The migration is **design only** and is not mounted.

## Principles

- The server stores **opaque, client-encrypted envelopes only**. It never sees, derives or stores
  plaintext, vault keys, KDF salts/parameters, wrapped keys or PRF material. Everything a client needs
  to unlock a vault besides the user's own secrets (passphrase/passkey PRF) lives **inside** the
  ciphertext or on the client.
- **Fail closed.** Unknown versions, unknown fields, malformed encodings, missing or legacy sessions,
  unsupported repositories and storage errors all reject the request. Nothing falls back to
  server-held keys (`utils/cypher.js` is not used for envelopes).
- **Per-user isolation.** The owner always comes from the verified session token, never from the
  request. Every query filters on the owner key.
- **Optimistic concurrency.** Every write is a single-document compare-and-set on `revision`.

## Envelope format v1

```json
{ "v": 1, "ct": "<canonical base64url>" }
```

| field | rule |
|-------|------|
| `v`   | must be exactly the integer `1`. Any other value returns `400 Unsupported envelope version`. |
| `ct`  | canonical unpadded base64url. Decoded size must be 28 bytes or more (at least an AEAD nonce + tag) and 524288 bytes (512 KiB) or less. An oversize value returns `413`. |
| other | **any additional key is rejected** (`400`). This blocks `salt`, `kdf`, `key`, `iv` or `plaintext` side fields. |

The cipher suite, nonce, KDF parameters and any vault-format metadata belong inside `ct` and are
defined by the client spec. A future `v: 2` will need a server change to whitelist it, so
unknown versions are never stored blindly.

Limits: `vaultId` matches `^[a-z0-9][a-z0-9-]{0,31}$` and each user can have at most 8 envelopes.
The limit is checked before insert, so it is a *soft* bound: concurrent creates can exceed it by
the number of racing requests. Per-document size is a hard bound.

## Storage

Collection `vault_envelopes` (a constant, so no new environment config). Document:

```
{ _id: sha256hex(owner + "\0" + vaultId),   // deterministic → uniqueness without an extra index
  owner: sha256hex("jisme.vault.owner.v1\0" + uuid),
  vaultId, revision: <int ≥ 1>, envelope: { v, ct }, size, updatedAt: ISO string }
```

- Create = `insertOne` with the deterministic `_id`. A duplicate key means a concurrent or existing
  vault, which returns `409`.
- Replace = one `findOneAndUpdate({_id, owner, vaultId, revision: expected}, $set{…, revision: expected+1})`.
- Delete = one `findOneAndDelete({_id, owner, vaultId, revision: expected})`.
- The Mongo adapter handles this collection in a dedicated branch, so the generic ObjectId `_id`
  rewriting never applies. The mock adapter mirrors the semantics (single process only). The legacy
  Data API adapter is **refused** (`503`) because it cannot provide these atomic primitives.
- The owner key is a domain-separated SHA-256 of the session uuid. It does not depend on
  `ENCRYPTION_PRIVATE_KEY` or `HASH_SALT`, so key rotation cannot orphan vaults, and the raw uuid
  is not stored.

## Endpoints (Express + Netlify `vaults` function)

Every endpoint needs `Authorization: Bearer <token>`. The token must be a fully authenticated
session (`isAuthorized === true`), contain a uuid, and carry an integer `auth_time`, the same rule
as `generateFreshSessionResolver`. Pre-auth tokens and legacy tokens without `auth_time` get `401`.
The client must sign in again. Every handler rejects PRF-named keys anywhere in the body or query
(`400`, the same guard as the user endpoints).

| method & path | body / query | success |
|---------------|--------------|---------|
| `GET /vaults` | – | `200 {vaults:[{vaultId, revision, size, v, updatedAt}]}` (no ciphertext) |
| `GET /vaults/:vaultId` | – | `200 {vaultId, revision, updatedAt, envelope}`; `404` if absent |
| `PUT /vaults/:vaultId` | `{expectedRevision, envelope}` | `expectedRevision: 0` = create only (`201`); `n ≥ 1` = replace only if current is `n` (`200`). Returns `{vaultId, revision, updatedAt}` |
| `DELETE /vaults/:vaultId?expectedRevision=n` | – | `200 {vaultId, deleted:true}`. Requires **recent authentication**: `auth_time` 300 s old or less, otherwise `401 Reauthentication required` |

Error cases:

| code | when |
|------|------|
| 400 | malformed vaultId, body not an object, unknown top-level or envelope keys, bad `expectedRevision`, non-canonical/too-short `ct`, unsupported `v`, PRF material |
| 401 | missing, invalid, pre-auth or legacy (no `auth_time`) session; stale session on DELETE |
| 403 | creating beyond the per-user vault limit |
| 404 | GET of an absent vault |
| 409 | revision mismatch on create/replace/delete. Returns `{error, currentRevision}` (0 = absent) and **never the envelope**. The client must re-fetch, merge locally, and retry |
| 413 | `ct` larger than 512 KiB |
| 503 | unsupported repository (Data API) or storage failure. Generic message, no internals |

Transport body limits: Express parses `/vaults` bodies with a dedicated 1 MB JSON parser
(other routes keep the 100 kB default). Netlify sync functions accept roughly 6 MB.

## Migration of existing accounts (design only, NOT mounted)

Today `accounts` rows are encrypted with the server key. Goal: move each user to one client-encrypted
envelope, then remove the server-decryptable copies. The process must be resumable, atomic at its
commit point, and never leave the user with neither copy.

1. **Lock (legacy-blocking, follow-up).** CAS the user document from `vault_migration` absent to
   `{state:"staging", vaultId, startedAt, legacyDigest}`. `legacyDigest` = count + max
   `last_update_date` of the user's accounts. While the state is `staging`, legacy account writes
   return `423` so the snapshot cannot drift. Re-entering this step is idempotent.
2. **Stage (resumable).** The client reads legacy accounts through the existing API, encrypts them
   locally into an envelope, and writes it to a *staging* sub-document on the target vault doc:
   `staging: {envelope, revision, legacyDigest}`. Staging is CAS-versioned like a normal write, so
   a crashed client re-stages from scratch or continues from the stored staging revision. The live
   `envelope` is untouched.
3. **Finalize (atomic commit point).** One `findOneAndUpdate` on the vault doc, conditioned on
   `staging.revision` and `staging.legacyDigest == current digest`. It promotes `staging.envelope`
   to `envelope`, bumps `revision`, sets `migratedAt`, and unsets `staging`. Then the user state is
   CAS-set from `staging` to `finalized`. If the process crashes between the two, a retry sees the
   vault already promoted (`migratedAt` set) and only completes the user state.
4. **Purge (destructive, follow-up, separately authorized).** Idempotent batched deletion of the
   user's legacy `accounts` rows when state is `finalized`, followed by `state:"client-only"`. Only
   after a client has confirmed it can decrypt the finalized envelope (explicit acknowledgement call).
5. **Abort.** Before finalize, an abort CASes the state back to absent and unsets `staging`. Legacy
   data was never modified.

There is no server-side decryption or re-encryption of account data in any step. The server never
holds a client key.

## Explicit follow-ups

- Mount steps 1–5 above (legacy write lock, stage/finalize/abort/purge endpoints), with tests against a real isolated Mongo.
- Rate limiting and an exact per-user quota (counter document or fixed slot set).
- Optionally `ETag`/`If-Match` mapping of `revision` (requires CORS `Allow-Headers` changes).
- Client spec for the contents of `ct` (AEAD suite, KDF, PRF/passphrase wrapping, recovery), kept client-side.
- Envelope format v2 negotiation when needed.
