document.addEventListener('DOMContentLoaded', () => {
  // Mobile menu toggle (responsive sidebar)
  const mobileToggleBtn = document.querySelector('.mobile-menu-toggle');
  if (mobileToggleBtn) {
    mobileToggleBtn.addEventListener('click', function () {
      const nav = document.querySelector('.sidebar nav');
      if (!nav) return;
      nav.classList.toggle('mobile-visible');
      const isExpanded = nav.classList.contains('mobile-visible');
      this.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    });
  }

  // Load user details
  const username = localStorage.getItem('username');
  const userEmail = localStorage.getItem('userEmail');
  const userPicture = localStorage.getItem('userProfilePicture');

  const profileNameEl = document.querySelector('.profile-name');
  const profileEmailEl = document.querySelector('.profile-email');
  if (username && profileNameEl && profileEmailEl) {
    profileNameEl.textContent = username;
    profileEmailEl.textContent = userEmail || `${username}@company.com`;

    if (userPicture) {
      const profileImg = document.getElementById('profileImage');
      const profileEmoji = document.getElementById('profileEmoji');
      if (profileImg && profileEmoji) {
        profileImg.src = userPicture;
        profileImg.style.display = 'block';
        profileEmoji.style.display = 'none';
      }
    }
  }

  // Dark mode initial state + toggle
  const darkModeBtn = document.querySelector('[aria-label="Toggle Dark Mode"]');
  if (localStorage.getItem('darkMode') === 'true') {
    document.body.classList.add('dark-mode');
    if (darkModeBtn) darkModeBtn.textContent = '☀️';
  }
  if (darkModeBtn) {
    darkModeBtn.addEventListener('click', function () {
      document.body.classList.toggle('dark-mode');
      const isDark = document.body.classList.contains('dark-mode');
      localStorage.setItem('darkMode', String(isDark));
      this.textContent = isDark ? '☀️' : '🌙';
    });
  }

  // Logout
  const logoutBtn = document.querySelector('.logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (typeof showConfirm !== 'function') {
        // Fallback if modal.js isn't loaded for some reason
        localStorage.clear();
        window.location.href = 'signin.html';
        return;
      }
      if (await showConfirm('Are you sure you want to logout?', 'Confirm Logout')) {
        localStorage.clear();
        window.location.href = 'signin.html';
      }
    });
  }

  // Policies Overview donuts
  const clampPct = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) return 0;
    return Math.max(0, Math.min(100, num));
  };

  const setDonut = ({ arcEl, labelEl, pct }) => {
    if (!arcEl || !labelEl) return;

    const radius = Number(arcEl.getAttribute('r')) || 50;
    const circumference = 2 * Math.PI * radius;
    const normalized = clampPct(pct);

    arcEl.setAttribute('stroke-dasharray', `${circumference}`);
    const dashOffset = circumference * (1 - normalized / 100);
    arcEl.setAttribute('stroke-dashoffset', `${dashOffset}`);

    labelEl.textContent = `${normalized}%`;
  };

  async function loadPolicyCompliance() {
    const passwordArc = document.getElementById('passwordPolicyArc');
    const passwordPctEl = document.getElementById('passwordPolicyPct');
    const backupArc = document.getElementById('backupPolicyArc');
    const backupPctEl = document.getElementById('backupPolicyPct');

    // If the template doesn't have these IDs yet, do nothing.
    if (!passwordArc || !passwordPctEl || !backupArc || !backupPctEl) return;

    try {
      const resp = await api.get('/dashboard-stats');
      if (!resp.ok) {
        if (resp.status === 401) window.location.href = 'signin.html';
        return;
      }
      const data = await resp.json();

      const passwordRate = data?.policy_compliance?.password;
      const backupRate = data?.policy_compliance?.backup;

      setDonut({ arcEl: passwordArc, labelEl: passwordPctEl, pct: passwordRate });
      setDonut({ arcEl: backupArc, labelEl: backupPctEl, pct: backupRate });
    } catch (e) {
      console.error('Failed to load policy compliance', e);
    }
  }

  if (typeof api !== 'undefined') {
    loadPolicyCompliance();
  }
});
