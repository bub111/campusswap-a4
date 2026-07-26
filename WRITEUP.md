# Assignment 4 — Write-up

## V1 · SQL Injection (`POST /login`, `GET /search`)

**Bug.** Both queries were built by concatenating user input into the SQL string,
so input like `quartermaster' -- ` closed the string literal and commented out the
password check (auth bypass), and a `UNION SELECT` on `/search` appended every
user's username and password through the 3-column result set (data exfiltration).

**Fix.** I replaced both sinks with bound parameterized queries (`db.prepare(...).get(username, password)`
and `... WHERE title LIKE ?` with `'%'+q+'%'` passed as the value). The database now
treats the input strictly as data, so quotes and `UNION` are literal characters,
not SQL. Normal login and search still work unchanged.

## V2 · Stored XSS (comments on `/item/:id`)

**Bug.** The comment body was stored verbatim and rendered into the page with
`${c.body}` — no escaping — so a `<script>` comment executed for every visitor.
The session cookie also lacked `HttpOnly`, letting injected JS read `document.cookie`
and steal the session.

**Fix (defense in depth).** (1) Output encoding: the comment body is now rendered
through the existing `esc()` helper, so `<script>` becomes inert text. (2) A
`Content-Security-Policy` header (`script-src 'self'`) is set on every response, so
even a missed escaping bug won't run inline injected scripts. (3) The session cookie
is now `HttpOnly`, so JavaScript can no longer read it.

## V3 · CSRF (`POST /wallet/transfer`)

**Bug.** The transfer was authenticated only by the session cookie, which the browser
attaches to cross-site requests too, so any off-site page could auto-submit a transfer
as the logged-in victim.

**Fix.** I implemented the synchronizer token pattern: a random per-session `csrf`
token is generated at login, embedded as a hidden `_csrf` field in the transfer form,
and verified with a constant-time compare (`crypto.timingSafeEqual`) on submit —
requests without a matching token get `403`. I also set `SameSite=Strict` on the
session cookie so it isn't sent on cross-site requests. The off-site `csrf-poc.html`
no longer moves credits, but a legitimate transfer through the real form still works.
