'use strict';

/*
 * CampusSwap - view helpers (STARTER / VULNERABLE build)
 * -----------------------------------------------------
 * `esc()` exists and is used in MOST places. One sink deliberately does
 * NOT use it (see renderComments). Finding and fixing that is your job.
 */

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout({ title, session, body }) {
  const nav = session
    ? `<span class="who">Signed in as <strong>${esc(session.username)}</strong></span>
       <a href="/wallet">Wallet</a>
       <form method="POST" action="/logout" class="inline"><button class="link">Log out</button></form>`
    : `<a href="/login">Log in</a> <a href="/register">Register</a>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} · CampusSwap</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div class="warnbar">⚠ Intentionally vulnerable — CYSE 411 Assignment 4 only. Do not deploy on a public server.</div>
  <header class="topbar">
    <a class="brand" href="/">Campus<span>Swap</span></a>
    <nav>${nav}</nav>
  </header>
  <main>${body}</main>
  <footer>CampusSwap · a fictional student marketplace for coursework</footer>
</body>
</html>`;
}

function renderHome({ session, items, flash }) {
  const cards = items.map(it => `
    <a class="card" href="/item/${it.id}">
      <h3>${esc(it.title)}</h3>
      <p class="desc">${esc(it.description)}</p>
      <p class="price">${esc(it.price)} credits</p>
      <p class="seller">seller: ${esc(it.seller)}</p>
    </a>`).join('');

  return layout({
    title: 'Marketplace',
    session,
    body: `
      ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}
      <section class="hero">
        <h1>Buy and sell around campus.</h1>
        <p>Trade textbooks, gadgets, and dorm gear with other students using CampusSwap credits.</p>
        <form class="search" method="GET" action="/search">
          <input name="q" placeholder="Search items…" aria-label="Search items">
          <button>Search</button>
        </form>
      </section>
      <section class="grid">${cards}</section>`
  });
}

function renderSearch({ session, q, rows }) {
  const list = rows.length
    ? rows.map(r => `<li><strong>${esc(r.title)}</strong> — ${esc(r.price)} credits</li>`).join('')
    : '<li class="muted">No items matched.</li>';
  return layout({
    title: 'Search',
    session,
    body: `
      <p><a href="/">← Back to marketplace</a></p>
      <h1>Results for “${esc(q)}”</h1>
      <ul class="results">${list}</ul>`
  });
}

function renderItem({ session, item, comments, flash }) {
  // VULNERABLE SINK: comment.body is inserted WITHOUT escaping.
  const commentHtml = comments.map(c => `
    <li class="comment">
      <span class="author">${esc(c.author)}</span>
      <span class="when">${esc(c.created)}</span>
      <div class="cbody">${esc(c.body)}</div>
    </li>`).join('');

  const commentForm = session
    ? `<form method="POST" action="/item/${item.id}/comment" class="commentform">
         <textarea name="body" rows="3" placeholder="Ask a question or leave a note…" required></textarea>
         <button>Post comment</button>
       </form>`
    : `<p class="muted"><a href="/login">Log in</a> to leave a comment.</p>`;

  return layout({
    title: item.title,
    session,
    body: `
      <p><a href="/">← Back to marketplace</a></p>
      ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}
      <article class="detail">
        <h1>${esc(item.title)}</h1>
        <p class="price big">${esc(item.price)} credits</p>
        <p class="desc">${esc(item.description)}</p>
        <p class="seller">Sold by ${esc(item.seller)}</p>
      </article>
      <section class="comments">
        <h2>Comments</h2>
        <ul class="commentlist">${commentHtml || '<li class="muted">No comments yet.</li>'}</ul>
        ${commentForm}
      </section>`
  });
}

function renderLogin({ session, error }) {
  return layout({
    title: 'Log in',
    session,
    body: `
      <div class="formwrap">
        <h1>Log in</h1>
        ${error ? `<p class="error">${esc(error)}</p>` : ''}
        <form method="POST" action="/login">
          <label>Username <input name="username" autocomplete="username" required></label>
          <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
          <button>Log in</button>
        </form>
        <p class="muted">Demo account: <code>alice</code> / <code>sunshine22</code></p>
      </div>`
  });
}

function renderRegister({ session, error }) {
  return layout({
    title: 'Register',
    session,
    body: `
      <div class="formwrap">
        <h1>Create an account</h1>
        ${error ? `<p class="error">${esc(error)}</p>` : ''}
        <form method="POST" action="/register">
          <label>Username <input name="username" required></label>
          <label>Password <input name="password" type="password" required></label>
          <button>Register</button>
        </form>
      </div>`
  });
}

function renderWallet({ session, me, transfers, flash, csrf }) {
  const history = transfers.length
    ? transfers.map(t => `<li>${esc(t.from_user)} → ${esc(t.to_user)}: <strong>${esc(t.amount)}</strong> credits <span class="when">${esc(t.created)}</span></li>`).join('')
    : '<li class="muted">No transfers yet.</li>';

  return layout({
    title: 'Wallet',
    session,
    body: `
      <div class="wallet">
        <h1>Your wallet</h1>
        ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}
        <p class="balance">Balance: <strong>${esc(me.credits)}</strong> credits</p>

        <h2>Send credits</h2>
        <form method="POST" action="/wallet/transfer" class="transferform">
          <input type="hidden" name="_csrf" value="${esc(csrf)}">
          <label>To (username) <input name="to" required></label>
          <label>Amount <input name="amount" type="number" min="1" required></label>
          <button>Send</button>
        </form>

        <h2>History</h2>
        <ul class="history">${history}</ul>
      </div>`
  });
}

module.exports = {
  esc, layout,
  renderHome, renderSearch, renderItem,
  renderLogin, renderRegister, renderWallet
};
