/* ═══════════════════════════════════════════
   PUBLIC Rights — Theme Manager
   Shared across all pages
   ═══════════════════════════════════════════ */

(function() {
  // App name config - change here to update everywhere
  window.APP_NAME = "Public Rights";
  window.APP_TAGLINE = "Secure Portal";
  window.APP_ICON = "⚖️";

  // Apply saved theme immediately (before render)
  const saved = localStorage.getItem('pr-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
})();

function initTheme() {
  const current = localStorage.getItem('pr-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', current);

  // Update all toggle buttons on page
  document.querySelectorAll('.theme-toggle').forEach(btn => {
    updateToggleUI(btn, current);
  });

  // Update app names on page
  document.querySelectorAll('[data-app-name]').forEach(el => {
    el.textContent = window.APP_NAME;
  });
  document.querySelectorAll('[data-app-tagline]').forEach(el => {
    el.textContent = window.APP_TAGLINE;
  });
  document.querySelectorAll('[data-app-icon]').forEach(el => {
    el.textContent = window.APP_ICON;
  });
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('pr-theme', next);

  document.querySelectorAll('.theme-toggle').forEach(btn => {
    updateToggleUI(btn, next);
  });
}

function updateToggleUI(btn, theme) {
  const label = btn.querySelector('.toggle-label');
  if (label) {
    label.textContent = theme === 'dark' ? 'Light' : 'Dark';
  }
}

// Auto-init when DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTheme);
} else {
  initTheme();
}
