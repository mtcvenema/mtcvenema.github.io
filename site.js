// Shared header (menu) and footer for all pages.
// To change the menu or the footer, edit this file only.
(function () {
  'use strict';

  // ---- Menu: [label, section id on the main page] ----
  const MENU = [
    ['About', 'about'],
    ['Publications', 'publications'],
    ['Projects', 'projects'],
    ['Tools', 'tools'],
    ['Teaching', 'teaching'],
    ['Supervision', 'supervision'],
    ['Service', 'service'],
  ];

  // Main page: <body data-page="home"> uses in-page links (#about).
  // Other pages link to index.html#about. A page in a subfolder sets data-root, e.g.
  // <body data-root="../"> for acabella/index.html, so the links still reach the main page.
  const isHome = document.body.dataset.page === 'home';
  const root = document.body.dataset.root || '';
  const base = isHome ? '' : root + 'index.html';

  // ---- Header ----
  const header = document.getElementById('site-header');
  if (header) {
    const desktop = MENU.map(([label, id]) =>
      `<a class="navbar-item" href="${base}#${id}">${label}</a>`).join('\n        ');
    const mobile = MENU.map(([label, id]) =>
      `<a href="${base}#${id}">${label}</a>`).join('\n      ');
    header.outerHTML = `
  <header class="site-header">
    <nav class="navbar" role="navigation" aria-label="main navigation">
      <a class="navbar-logo" href="${isHome ? '#about' : root + 'index.html'}">Marloes <span>Venema</span></a>
      <div class="navbar-links">
        ${desktop}
      </div>
      <button class="navbar-hamburger" id="nav-toggle" aria-label="Open navigation">☰</button>
    </nav>
    <div class="nav-mobile-dropdown" id="nav-dropdown">
      ${mobile}
    </div>
  </header>`;

    // Mobile menu
    const navToggle = document.getElementById('nav-toggle');
    const navDropdown = document.getElementById('nav-dropdown');
    navToggle.addEventListener('click', () => navDropdown.classList.toggle('open'));
    navDropdown.querySelectorAll('a').forEach(a =>
      a.addEventListener('click', () => navDropdown.classList.remove('open')));
  }

  // ---- "Back to main page" button: added automatically at the top of every page except the main page ----
  if (!isHome) {
    const firstCard = document.querySelector('.card');
    if (firstCard) {
      firstCard.insertAdjacentHTML('afterbegin',
        `<div class="pub-links" style="margin:0 0 1rem;"><a class="pub-link" href="${root}index.html">&larr; back to main page</a></div>`);
    }
  }

  // ---- Footer ----
  const footer = document.getElementById('site-footer');
  if (footer) {
    // Last modified: the date the server reports for this page, as dd/mm/yy
    const d = new Date(document.lastModified);
    const p = n => String(n).padStart(2, '0');
    const modified = p(d.getDate()) + '/' + p(d.getMonth() + 1) + '/' + String(d.getFullYear()).slice(-2);
    footer.outerHTML = `
  <footer class="site-footer">
    <span>Marloes Venema · University of Wuppertal · Based on a design by <a href="https://provsec.org/doreen.html" target="_blank">Doreen Riepel</a></span>
    <span class="last-modified"><a href="${root}impressum.html">Impressum</a> \u00b7 <a href="${root}datenschutz.html">Privacy notice</a> \u00b7 Last modified: <span id="last-modified">${modified}</span></span>
  </footer>`;
  }
})();
