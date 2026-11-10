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
  Revisions never repeat for a given `(owner, vaultId)`, even across delete and re-create
  (tombstones, below), so a stale writer can never match a newer vault (no ABA).

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

Limits: `vaultId` matches `^[a-z0-9][a-z0-9-]{0,31}$`. Each user can have at most **8 live
vaults** and at most **64 distinct vault names** over time (live + deleted; this bounds tombstones).
Both are hard bounds enforced by one atomic reservation on a per-user quota document (below), so
concurrent creates cannot overshoot. Per-document size is a hard bound.

## Storage

Collection `vault_envelopes` (a constant, so no new environment config). Document:

```
{ _id: sha256hex(owner + "\0" + vaultId),   // deterministic → uniqueness without an extra index
  owner: sha256hex("jisme.vault.owner.v1\0" + uuid),
  vaultId, revision: <int ≥ 1>, envelope: { v, ct } | null, size, updatedAt: ISO string }
```

A document with `envelope: { v: 1, … }` is a **live** vault. A document with `envelope: null`
(and `size: 0`) is a **tombstone**: a deleted vault that keeps only its name and last revision,
never ciphertext. Reads, lists, replaces and deletes filter on `'envelope.v': 1`, so tombstones
behave exactly like absent vaults (`404`, `currentRevision: 0`).

- Create (new name) = `insertOne` with the deterministic `_id`, revision `1`. A duplicate key
  means a concurrent or existing vault, which returns `409`.
- Create (name with a tombstone) = one `findOneAndUpdate({_id, owner, vaultId, revision: t,
  envelope: null}, $set{envelope, …, revision: t+1})`. Revisions continue from the tombstone.
- Replace = one `findOneAndUpdate({_id, owner, vaultId, revision: expected, 'envelope.v': 1},
  $set{…, revision: expected+1})`.
- Delete = one `findOneAndUpdate({_id, owner, vaultId, revision: expected, 'envelope.v': 1},
  $set{envelope: null, size: 0, revision: expected+1})`, i.e. live → tombstone atomically.
- **Why tombstones (ABA):** without them a deleted-then-recreated vault restarted at revision 1,
  so a device holding the old revision 1 could silently overwrite the new vault. With them, the
  example *create (1) → delete (tombstone 2) → re-create (3)* makes an old `expectedRevision: 1`
  PUT or DELETE return `409`. The wire API is unchanged; clients must simply not assume a new
  vault starts at revision 1 (use the revision returned by the create).
- The Mongo adapter handles this collection in a dedicated branch, so the generic ObjectId `_id`
  rewriting never applies. The mock adapter mirrors the semantics (single process only).
- **Repository allowlist (fail closed):** vault storage is served only when
  `DB_REPOSITORY_TYPE=db`, or `DB_REPOSITORY_TYPE=mock` with `NODE_ENV !== 'production'`. Anything
  else (`api`, unset, unknown, `mock` in production) is **refused** (`503`) without contacting the
  adapter, because only Mongo provides these atomic primitives durably.

### Per-user quota (`vault_quotas`)

```
{ _id: owner, ids: [vaultId, …],   // live or in-flight vaults, at most 8
  names: <int> }                    // distinct names ever created, at most 64
```

- Create first **reserves** a slot with one conditional upsert:
  `findOneAndUpdate({_id, ids: {$ne: vaultId}, 'ids.7': {$exists: false}[, names: {$lt: 64}]},
  {$push: {ids: vaultId}, $inc: {names: 1 | 0}}, {upsert: true})`. The `names` condition and
  increment apply only to brand-new names. Re-using a tombstoned name costs a live slot only.
  A first-time upsert that loses an `E11000` race is retried once; a second `E11000` means "full".
- If the reservation is refused, the vault id already being held (live or in flight) yields `409`.
  Otherwise the user is at a limit, which yields `403`.
- If the vault write then loses its compare-and-set, the reservation is released (`$pull`). A
  successful delete releases the slot after tombstoning.
- **Failure mode:** if the process dies, or storage fails, between the reservation and the vault
  write (or between tombstoning and release), the slot stays held. This fails *closed*: the limit
  becomes stricter for that user and can never be exceeded. Repairing a drifted quota document is
  an operator task (recount the live vaults).
- The feature is unreleased, so no pre-existing vaults lack a quota document.
- The owner key is a domain-separated SHA-256 of the session uuid. It does not depend on
  `ENCRYPTION_PRIVATE_KEY` or `HASH_SALT`, so key rotation cannot orphan vaults, and the raw uuid
  is not stored.

## Endpoints (Express + Netlify `vaults` function)

Every endpoint needs `Authorization: Bearer <token>`. The token must be a fully authenticated
session (`isAuthorized === true`), contain a uuid, and carry an integer `auth_time`, the same rule
as `generateFreshSessionResolver`. Pre-auth tokens and legacy tokens without `auth_time` get `401`.
The client must sign in again.

**Order of checks:** the token is verified **first**. Unauthenticated requests get `401` before
the server walks their payload. Only then does the PRF guard (`400`, the same guard as the user
endpoints) reject PRF-named keys in the inputs each handler actually receives:

| handler | inputs checked for PRF names |
|---------|------------------------------|
| `GET /vaults`, `GET /vaults/:vaultId` | route params only. Query strings are **not read** by GET; `?prf=…` is ignored (neither rejected nor stored) |
| `PUT /vaults/:vaultId` | route params + JSON body. Query strings are **not read**; `?prf=…` is ignored |
| `DELETE /vaults/:vaultId` | route params + query string |

**Recent authentication** (`auth_time` 300 s old or less, and not in the future; otherwise
`401 Reauthentication required`) is required for every operation that can destroy an existing
vault: **DELETE**, and **PUT with `expectedRevision ≥ 1`** (replace). Replacing a vault with
arbitrary bytes is as destructive as deleting it, so a stale token cannot sidestep the delete rule
via PUT. Creating a new vault (`expectedRevision: 0`) does not need a recent sign-in. Any PUT body
that is not a clear create is treated as a replace for this check (fail closed). Clients should
expect to prompt for a fresh sign-in before saving changes to an existing vault.

| method & path | body / query | success |
|---------------|--------------|---------|
| `GET /vaults` | – | `200 {vaults:[{vaultId, revision, size, v, updatedAt}]}` (no ciphertext, live vaults only) |
| `GET /vaults/:vaultId` | – | `200 {vaultId, revision, updatedAt, envelope}`; `404` if absent or deleted |
| `PUT /vaults/:vaultId` | `{expectedRevision, envelope}` | `expectedRevision: 0` = create only (`201`; revision is `1` for a new name, or the tombstone's revision + 1 for a previously deleted name); `n ≥ 1` = replace only if current is `n` (`200`, recent auth). Returns `{vaultId, revision, updatedAt}` |
| `DELETE /vaults/:vaultId?expectedRevision=n` | – | `200 {vaultId, deleted:true}` (recent auth) |

Error cases:

| code | when |
|------|------|
| 400 | malformed vaultId, body not an object, unknown top-level or envelope keys, bad `expectedRevision`, non-canonical/too-short `ct`, unsupported `v`, PRF material |
| 401 | missing, invalid, pre-auth or legacy (no `auth_time`) session (checked before anything else); stale session on DELETE or replace |
| 403 | creating beyond 8 live vaults, or a brand-new name beyond 64 distinct names |
| 404 | GET of an absent or deleted vault |
| 409 | revision mismatch on create/replace/delete, or a create racing another create of the same id. Returns `{error, currentRevision}` (0 = absent) and **never the envelope**. `currentRevision` is read separately from the failed write, so it is a **hint only**: it can already be stale, or `0` after a concurrent delete. The client must re-fetch (GET), merge locally, and retry with the fetched revision |
| 413 | `ct` larger than 512 KiB |
| 503 | unsupported/refused repository or storage failure. Generic message, no internals |

Transport body limits: Express parses `/vaults` bodies with a dedicated 1 MB JSON parser
(other routes keep the 100 kB default). Netlify sync functions accept roughly 6 MB.

Netlify transport: the function parses `event.body` as JSON text and does **not** decode
`isBase64Encoded` bodies. A base64-encoded body (which Netlify produces for non-text content
types) fails JSON parsing and returns `400 Body must be JSON`. This fails closed, so clients must
send `Content-Type: application/json`.

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
- Rate limiting (the per-user quota is now exact; request rate is still unbounded).
- Tests against a real isolated Mongo for the atomic primitives (`E11000`, conditional upsert,
  `includeResultMetadata: false`, `returnDocument: 'after'`). Adapter tests currently use driver doubles.
- Express parser errors (413 / bad JSON on `/vaults`) still go to Express's default handler,
  without CORS headers (review L4).
- Optionally `ETag`/`If-Match` mapping of `revision` (requires CORS `Allow-Headers` changes).
- Client spec for the contents of `ct` (AEAD suite, KDF, PRF/passphrase wrapping, recovery), kept client-side.
- Envelope format v2 negotiation when needed.
