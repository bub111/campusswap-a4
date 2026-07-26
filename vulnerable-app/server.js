'use strict';

/*
 * CampusSwap — server (STARTER / VULNERABLE build)
 * ================================================
 * This file contains THREE intentional vulnerabilities for CYSE 411 A4:
 *
 *   [V1] SQL Injection      -> POST /login  and  GET /search
 *   [V2] Stored XSS         -> comments on /item/:id  (+ no CSP, cookie readable by JS)
 *   [V3] CSRF               -> POST /wallet/transfer  (no anti-CSRF token, loose cookie)
 *
 * Each is marked with a `VULN` banner comment. Do not "clean up" other code
 * unless it is one of the three sinks — keep your diff focused.
 */

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const { db, createSchema } = require('./db');
const V = require('./views');

createSchema();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// FIX [V2]: Content-Security-Policy on every response. script-src 'self' means
// inline injected <script> won't execute even if an escaping bug slips through.
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; " +
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ---- Tiny in-memory session store -----------------------------------------
// sessions: sid -> { userId, username }
const sessions = new Map();

function startSession(res, user) {
  const sid = crypto.randomBytes(24).toString('hex');
  // FIX [V3]: per-session CSRF token (synchronizer token pattern).
  const csrf = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { userId: user.id, username: user.username, csrf });

  // FIX [V2]/[V3]: HttpOnly hides the cookie from JS (blocks XSS cookie theft);
  // SameSite 'strict' stops the cookie riding along on cross-site requests (CSRF).
  res.cookie('sid', sid, { path: '/', httpOnly: true, sameSite: 'strict' });
}

app.use((req, res, next) => {
  const sid = req.cookies.sid;
  req.session = sid && sessions.has(sid) ? sessions.get(sid) : null;
  req.sid = sid;
  next();
});

function currentUser(req) {
  if (!req.session) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId) || null;
}

// ---- Home ------------------------------------------------------------------
app.get('/', (req, res) => {
  const items = db.prepare(`
    SELECT items.id, title, description, price, users.username AS seller
    FROM items JOIN users ON users.id = items.seller_id
    ORDER BY items.id DESC
  `).all();
  res.send(V.renderHome({ session: req.session, items, flash: req.query.msg }));
});

// ---- Search ----------------------------------------------------------------
app.get('/search', (req, res) => {
  const q = req.query.q || '';

  // ============================ VULN [V1] SQL Injection =====================
  // FIX: bind the search term as a parameter; the % wildcards go in the value.
  let rows = [];
  try {
    rows = db.prepare('SELECT id, title, price FROM items WHERE title LIKE ?')
             .all('%' + q + '%');
  } catch (e) {
    rows = [];
  }
  // =========================================================================
  res.send(V.renderSearch({ session: req.session, q, rows }));
});

// ---- Auth ------------------------------------------------------------------
app.get('/login', (req, res) => {
  res.send(V.renderLogin({ session: req.session, error: req.query.error }));
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // ============================ VULN [V1] SQL Injection =====================
  // FIX: use a bound parameterized query so input is treated as data, never SQL.
  let user = null;
  try {
    user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
             .get(username, password);
  } catch (e) {
    user = null;
  }
  // =========================================================================

  if (!user) {
    return res.send(V.renderLogin({ session: req.session, error: 'Invalid username or password.' }));
  }
  startSession(res, user);
  res.redirect('/?msg=' + encodeURIComponent('Welcome back, ' + user.username + '!'));
});

app.get('/register', (req, res) => {
  res.send(V.renderRegister({ session: req.session, error: req.query.error }));
});

app.post('/register', (req, res) => {
  const { username = '', password = '' } = req.body;
  if (!username.trim() || !password) {
    return res.send(V.renderRegister({ session: req.session, error: 'Username and password are required.' }));
  }
  try {
    const info = db.prepare('INSERT INTO users (username, password, credits) VALUES (?, ?, 100)')
      .run(username.trim(), password);
    startSession(res, { id: info.lastInsertRowid, username: username.trim() });
    res.redirect('/?msg=' + encodeURIComponent('Account created. You have 100 starter credits.'));
  } catch (e) {
    res.send(V.renderRegister({ session: req.session, error: 'That username is taken.' }));
  }
});

app.post('/logout', (req, res) => {
  if (req.sid) sessions.delete(req.sid);
  res.clearCookie('sid', { path: '/' });
  res.redirect('/');
});

// ---- Item detail + comments -----------------------------------------------
app.get('/item/:id', (req, res) => {
  const item = db.prepare(`
    SELECT items.*, users.username AS seller
    FROM items JOIN users ON users.id = items.seller_id
    WHERE items.id = ?
  `).get(req.params.id);
  if (!item) return res.status(404).send(V.layout({ title: 'Not found', session: req.session, body: '<h1>Item not found</h1>' }));

  const comments = db.prepare('SELECT * FROM comments WHERE item_id = ? ORDER BY id ASC').all(item.id);
  res.send(V.renderItem({ session: req.session, item, comments, flash: req.query.msg }));
});

app.post('/item/:id/comment', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');

  const body = req.body.body || '';

  // ============================ VULN [V2] Stored XSS =======================
  // The comment body is stored as-is and later rendered without escaping
  // (see views.js -> renderItem). Any HTML/JS a user submits becomes part
  // of the page for everyone who views this item.
  db.prepare('INSERT INTO comments (item_id, author, body) VALUES (?, ?, ?)')
    .run(req.params.id, user.username, body);
  // =========================================================================

  res.redirect('/item/' + req.params.id + '?msg=' + encodeURIComponent('Comment posted.'));
});

// ---- Wallet + transfer -----------------------------------------------------
app.get('/wallet', (req, res) => {
  const me = currentUser(req);
  if (!me) return res.redirect('/login');
  const transfers = db.prepare(
    'SELECT * FROM transfers WHERE from_user = ? OR to_user = ? ORDER BY id DESC LIMIT 20'
  ).all(me.username, me.username);
  res.send(V.renderWallet({ session: req.session, me, transfers, flash: req.query.msg, csrf: req.session.csrf }));
});

app.post('/wallet/transfer', (req, res) => {
  const me = currentUser(req);
  if (!me) return res.redirect('/login');

  // ============================ VULN [V3] CSRF =============================
  // FIX: require a valid per-session CSRF token, compared in constant time.
  const provided = req.body._csrf || '';
  const expected = req.session.csrf || '';
  const ok = provided.length === expected.length && expected.length > 0 &&
    crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  if (!ok) return res.status(403).send('CSRF token missing or invalid');
  // =========================================================================

  const to = (req.body.to || '').trim();
  const amount = parseInt(req.body.amount, 10);
  // =========================================================================

  if (!to || !Number.isInteger(amount) || amount <= 0) {
    return res.redirect('/wallet?msg=' + encodeURIComponent('Enter a valid recipient and amount.'));
  }
  const recipient = db.prepare('SELECT * FROM users WHERE username = ?').get(to);
  if (!recipient) {
    return res.redirect('/wallet?msg=' + encodeURIComponent('No such user: ' + to));
  }
  if (recipient.id === me.id) {
    return res.redirect('/wallet?msg=' + encodeURIComponent('You cannot send credits to yourself.'));
  }
  if (me.credits < amount) {
    return res.redirect('/wallet?msg=' + encodeURIComponent('Not enough credits.'));
  }

  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(amount, me.id);
    db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(amount, recipient.id);
    db.prepare('INSERT INTO transfers (from_user, to_user, amount) VALUES (?, ?, ?)')
      .run(me.username, recipient.username, amount);
  });
  tx();

  res.redirect('/wallet?msg=' + encodeURIComponent(`Sent ${amount} credits to ${recipient.username}.`));
});

app.listen(PORT, () => {
  console.log(`CampusSwap (VULNERABLE build) running at http://localhost:${PORT}`);
  console.log('Run "npm run seed" first if you have not seeded the database.');
});
