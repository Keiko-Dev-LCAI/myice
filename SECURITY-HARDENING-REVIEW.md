# MyICE security hardening — local build for review (2026-08-26)

**Status:** local only. **Do not deploy contract or push until Keiko gives a separate go.**

## What was built

### Contract — `MyICEStoreV2.sol` (new file; V1 left intact)
- `onlySponsor` on `storeFor` / `storeEmergencyFor` — closes “anyone can overwrite any record.”
- User EIP-191 signature + per-user `nonces[user]` replay protection.
- `deleteRecord()` unchanged (user-signed).
- `setSponsor` owner-only.

### Server — `myice-server.py` (guards added)
- `/api/store-health`: per-address **1 / 5 min** + per-IP rate limit (docstring now real).
- AI routes (`/api/chat`, analyze-*, etc.): before_request gate — per-IP + per-address rate limits, concurrency cap, **daily LCAI spend cap** (`DAILY_LCAI_CAP`, default 50).
- Server-side premium check stub: `PREMIUM_WHITELIST` env (comma-separated addresses). Client-only premium is no longer enough for AI when whitelist/TEST_MODE is unset → **402**.
- Sponsor key still from `LIGHTCHAIN_PRIVATE_KEY` env only.

## Critical product constraint (read this)

Today’s MyICE accounts use a **password-derived hash “address”**, not an ECDSA keypair
(`deriveOnChainAddress` = SHA-256 truncated). **`ecrecover` cannot verify those addresses.**

| Approach | Closes open contract writes | Proves user intent | Fits current accounts |
|----------|----------------------------|--------------------|------------------------|
| **V2 `onlySponsor` only** | Yes | No (trusts server) | Yes — **recommended phase 1** |
| **V2 full ecrecover** | Yes | Yes | Needs **EOA / secp256k1 migration** + re-sync |
| Server HMAC from password | N/A | Yes if server learns secret | Avoid — server should stay password-blind |

**Recommendation for Claude/Keiko:**  
1. Ship phase 1: deploy V2 with **onlySponsor** (can temporarily omit sig checks or keep them for future EOAs).  
2. Plan account migration to real keys (or password→secp256k1) before relying on on-chain sigs.  
3. Wire premium: on successful payment verify, add address to a durable premium store / whitelist — not only `localStorage`.

## Migration impact
New contract = new address → update `STORE_ADDR` / `MYICE_STORE_ADDRESS` → users **re-sync**. On-device vaults are not lost.

## Env knobs
`CHAT_RATE_PER_MIN`, `CHAT_RATE_PER_DAY`, `STORE_RATE_PER_5MIN`, `IP_RATE_PER_MIN`, `DAILY_LCAI_CAP`, `LCAI_PER_JOB`, `MAX_CONCURRENT_JOBS`, `PREMIUM_WHITELIST`, `PAYMENT_WALLET`, `TEST_MODE`.

## Not done (needs separate go)
- Mainnet/testnet contract deploy  
- Frontend EIP-191 signing / EOA migration  
- Durable premium DB  
- Push to GitHub / myice.win

## Phase 1 (2026-08-26 follow-up)

- **Deploy candidate:** `MyICEStorePhase1.sol` — `onlySponsor`, V1 function shapes (no ecrecover).
- **Shelf:** `MyICEStoreV2.sol` — full signed meta-tx; header marked **NOT DEPLOYABLE YET**.
- **Server:** `PREMIUM_ENFORCE` defaults **false**; AI routes reject missing `address` (400).
  Rate limits + daily LCAI cap remain on. Flip `PREMIUM_ENFORCE=true` only after a durable premium store exists.

### Future (not built)
1. Durable premium DB (verify payment → persist address) so 402 gate can be enforced.
2. Account migration to real secp256k1 / EOAs so `MyICEStoreV2` becomes deployable.

## On-chain delete + crypto-shred (2026-08-26)

- Phase1 adds `deleteFor(address)` (sponsor-only).
- Server: `POST /api/delete-health` (same rate limit as store).
- Frontend: Settings → **Erase my blockchain record** = delete on-chain + destroy emergency key + local wipe, with honest permanence notice.
- Residual (phase-1): endpoint trusts `address` in body (no user sig) — same as store-health until EOA migration.
- Deploys with Phase1 contract cutover (not alone). Live contract today has no `deleteFor` until that deploy.
