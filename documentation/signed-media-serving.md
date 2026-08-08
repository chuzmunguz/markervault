# Signed Media URLs + Browser Caching (design + rationale)

> **STATUS: IMPLEMENTED.** Signed self-authenticating URLs for photos/thumbs/avatars
> (with serve-time access re-check) built Jul 2026. Avatar caching layer (bucketed
> `exp` + `v=mtime_ns` + `Cache-Control`) built Jul 17 2026. `Cache-Control` extended
> to photos/thumbs Jul 18 2026 (commit `7e60084`). This doc records the mechanism and
> its rationale — nothing here is pending.

> **Scope in one line:** how `/photos`, `/thumbs`, and `/avatars` authorize without a
> Bearer header, why their responses are browser-cacheable anyway, why a content
> change (avatar re-upload, photo replace) always beats the cache, and the one
> accepted residue — a revoked viewer can replay already-cached images for up to
> 30 minutes.

---

## Motivation

Two constraints pull against each other:

1. **A browser `<img src>` cannot send an `Authorization` header.** So the media
   routes are deliberately public (no `@require_auth`) and authorization must travel
   inside the URL itself.
2. **Galleries are bursty.** A marker with dozens of photos fires dozens of image
   requests at once. Every request that reaches the server costs an HMAC
   verification, a DB access re-check, and an nginx handoff. Naively signed URLs
   (fresh `exp` on every payload) are unique every time, so the browser cache never
   hits and every render refetches everything — tolerable on a LAN, painful on
   anything slower (cellular being the motivating case).

The design resolves this with three layers: **authorization in the URL**, **URL
stability** (so cache hits are *possible*), and an explicit **`Cache-Control`**
header (so cache hits actually *happen*). The result is one fetch per image per
~30-minute window, while every request that does reach the server still re-checks
access against the live DB.

## Layer 1 — the self-authenticating signed URL (authorization)

`sign_photo_url(kind, filename, user_id)` produces
`/{kind}/{filename}?exp=...&uid=...&sig=...` where `sig` is HMAC-SHA256 over
`kind:filename:exp:uid` keyed with `ACCESS_TOKEN_SECRET`. TTL is `PHOTO_URL_TTL`
(1 h). The `uid` is the user the URL was **issued to** and is covered by the HMAC.

At serve time (`_serve_signed` for photos/thumbs, `serve_avatar` for avatars), after
the IP allowlist and rate limit:

- signature and expiry are verified (`verify_photo_sig`, constant-time compare);
- access is **re-checked fresh**: photos/thumbs resolve the owning map and require
  `user_can_access_map(map_id, uid)`; avatars require the users row to still name
  exactly this filename;
- the byte transfer is handed to nginx via `X-Accel-Redirect` (Flask never streams
  the file).

The re-check is why revocation works *within* a URL's lifetime: un-share a map and
the outstanding URLs die on their next server round-trip, TTL notwithstanding.

**The one sentence to keep in mind for everything below:** a response served from
the browser's cache never reaches the server, so it skips the re-check. The entire
trade-off surface of this design is exactly that sentence.

## Layer 2 — URL stability (making cache hits possible)

A browser caches by full URL. If any query parameter changes between two issuances,
the cache misses. So:

- **`exp` is bucketed, not continuous.** It is rounded up to a half-TTL boundary
  (`(now // 1800 + 2) * 1800`), giving each URL 30–60 min of validity and — the
  actual point — making repeated issuances within a bucket **byte-identical**.
  Re-renders and payload refetches inside the window reuse the same URL.
- **Avatar `v=mtime_ns`** (`_avatar_url`) is a *content version* appended outside
  the HMAC-covered fields: the avatar file's mtime in nanoseconds. It only moves
  when the file is rewritten, so it is stable across issuances — and it must
  **never be random** (a random `v` makes every URL unique and silently disables
  caching while everything still *looks* correct).
- Photos/thumbs carry no `v` — they don't need one; see the cache-busting section.

## Layer 3 — `Cache-Control: private, max-age=1800` (making cache hits happen)

All three success paths send `Cache-Control: private, max-age=1800`.

- Without an explicit header, browsers fall back to heuristic caching and tend to
  revalidate — a gallery re-fires its requests on every visit even though the URLs
  are stable. The header is what converts URL stability into actual cache hits.
- `private`: browser cache only, never shared proxies — the URLs are per-user and
  the content is access-controlled.
- `max-age=1800` matches the `exp` bucket half-TTL: past ~30 min the issued URL
  changes anyway, so a longer max-age would only extend the revocation residue
  (below) without saving any additional fetches.
- The header is set only on the success path. The 403/404 branches `abort()` before
  it, so denials are never cacheable.

## Cache-busting: why a content change always beats the cache

This is the non-evident part. The guarantee is the same for both kinds — **reload
the page/data and you see the new image; a stale copy can only appear on a page
that was rendered before the change and never reloaded since** — but the mechanism
is different:

| | filename | change mechanism | what busts the cache | stale window (idle page) |
|---|---|---|---|---|
| photos/thumbs | immutable content: fresh `name_<uuid>` per upload | `replace_photo` mints a **new filename** (same-name replace is rejected) | the URL itself changes; old URL 404s server-side (DB row gone) | none — old cached copy just becomes unreferenced |
| avatars | stable per user, overwritten in place | file rewritten under the same name | `v=mtime_ns` bumps → new URL on next payload | ≤ 30 min; then revalidation of the *old* URL returns the *new* bytes anyway (`v` is not in the HMAC) |

The photo row is why photos/thumbs get away without a version parameter: a given
filename's bytes can never change, so a cached photo can never be *stale* — only
*orphaned*. Avatars are the harder case precisely because their filename is reused;
`v` exists to solve exactly that, and only that.

## The accepted residue (deliberate, named at every step)

A viewer whose access is revoked — or whose target is deleted — can replay
already-cached images from their own browser for up to `max-age` (30 min). Nothing
new is fetchable (any request reaching the server re-checks and dies), but what
their browser already holds keeps rendering.

This was weighed and accepted for avatars on Jul 17 2026 and knowingly extended to
photos/thumbs on Jul 18 2026. It is bounded, local to that viewer's device, and
covers only content they were authorized to see when it was fetched. If it ever
becomes unacceptable, the knob is `max-age` (shorter window ⇄ weaker caching) — not
the signing scheme, which is unaffected.

Separately, the signed URL itself is bearer-like for its 30–60 min validity: anyone
holding the exact URL can fetch, gated by the IP allowlist and by the *issued*
`uid`'s current access. That is inherent to `<img>`-compatible auth and predates the
caching layer.

## Invariants — do not break these

1. **Never make `v` random, never issue per-request `exp`.** Either one destroys
   URL byte-stability and silently turns caching off while all tests still pass.
2. **Never replace a photo under the same filename.** Filename immutability is the
   entire reason photos/thumbs need no version parameter. `replace_photo` enforces
   this; keep it enforced.
3. **Keep `max-age` ≤ the `exp` bucket (1800 s) and keep `private`.** Longer buys
   no cache hits, only residue; non-private leaks per-user media into shared caches.
4. **Cache headers on success paths only.** Denials must stay uncacheable.
5. **Changing the HMAC message format invalidates every outstanding URL** at the
   moment of deploy. That's acceptable (they're short-lived) but do it knowingly.
6. **Test homes:** `tests/test_phase4.py` (photo/thumb URL stability + header),
   `tests/test_avatar.py` (avatar header + `v` semantics). A change to any layer
   lands with its suite.

## Code pointers

All in `backend.py`: `sign_photo_url` / `verify_photo_sig` / `_avatar_url` (the
signing block, with the bucketing and `v` comments), `_serve_signed` (photos +
thumbs), `serve_avatar` (avatar route with the DB re-check), `PHOTO_URL_TTL`.
