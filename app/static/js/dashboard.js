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

    // Load Dashboard Stats
    async function loadDashboardStats() {
      // Personalize Welcome Message
      const username = localStorage.getItem("username");
      const userEmail = localStorage.getItem("userEmail");
      const userPicture = localStorage.getItem("userProfilePicture");
      if (username) {
        document.querySelector(".profile-name").textContent = username;
        document.querySelector(".profile-email").textContent = userEmail || username + "@company.com";
        document.querySelector(".welcome-text").textContent = "Welcome " + username + "!";

        // Load profile picture
        if (userPicture) {
          document.getElementById('profileImage').src = userPicture;
          document.getElementById('profileImage').style.display = 'block';
          document.getElementById('profileEmoji').style.display = 'none';
        }
      }

      try {
        const resp = await api.get('/dashboard-stats');
        if (!resp.ok) {
          if (resp.status === 401) window.location.href = 'signin.html';
          return;
        }
        const data = await resp.json();

        // Update Overview Stats
        document.querySelector('.stat-box:nth-child(1) .stat-number').textContent = data.compliance_rate + '%';
        document.querySelector('.stat-box:nth-child(2) .stat-number').textContent = data.active_alerts;
        document.querySelector('.stat-box:nth-child(3) .stat-number').textContent = data.pending_reports;

        // Update Pie Chart Data
        const clampPct = (value) => {
          const num = Number(value);
          if (!Number.isFinite(num)) return 0;
          return Math.max(0, Math.min(100, num));
        };

        const pwd = clampPct(data?.policy_breakdown?.password);
        const backup = clampPct(data?.policy_breakdown?.backup);

        // Update donut (continuous) via CSS variables
        const chartContainer = document.querySelector('.chart-container');
        if (chartContainer) {
          chartContainer.style.setProperty('--policy-password-pct', String(pwd));
        }

        // Update the percentage texts
        // Positions are fixed in CSS:
        // - .chart-percentage is bottom-left (Backup)
        // - .chart-percentage-secondary is top-right (Password)
        const backupLabel = document.querySelector('.chart-percentage .chart-label-lg');
        const passwordLabel = document.querySelector('.chart-percentage-secondary .chart-label-lg');
        if (backupLabel) backupLabel.textContent = `${backup}%`;
        if (passwordLabel) passwordLabel.textContent = `${pwd}%`;

      } catch (e) {
        console.error('Failed to load stats', e);
      }
    }

    loadDashboardStats();

    // Load Alerts (dynamic) from notifications API
    const formatRelativeTime = (dateValue) => {
      const date = new Date(dateValue);
      const ms = date.getTime();
      if (!Number.isFinite(ms)) return '';

      const diffSec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
      if (diffSec < 30) return 'Just now';
      if (diffSec < 60) return `${diffSec}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin} min${diffMin === 1 ? '' : 's'} ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr} hour${diffHr === 1 ? '' : 's'} ago`;
      const diffDay = Math.floor(diffHr / 24);
      return `${diffDay} day${diffDay === 1 ? '' : 's'} ago`;
    };

    let dashboardAlertsTimeIntervalId = null;
    const startDashboardAlertsTimeTicker = (listEl) => {
      if (dashboardAlertsTimeIntervalId) {
        clearInterval(dashboardAlertsTimeIntervalId);
        dashboardAlertsTimeIntervalId = null;
      }
      if (!listEl) return;

      const update = () => {
        const timeEls = listEl.querySelectorAll('.alert-time[data-ts]');
        for (const el of timeEls) {
          const ts = el.getAttribute('data-ts');
          el.textContent = formatRelativeTime(ts);
        }
      };

      update();
      // Keep it lightweight; update relative times periodically.
      dashboardAlertsTimeIntervalId = setInterval(update, 30000);
    };

    const mapTypeToSeverity = (type) => {
      const t = String(type || '').toLowerCase();
      if (t === 'critical' || t === 'error') return { cls: 'high', label: 'High' };
      if (t === 'warning') return { cls: 'medium', label: 'Medium' };
      return { cls: 'low', label: 'Low' };
    };

    async function loadDashboardAlerts() {
      const listEl = document.getElementById('dashboardAlertsList');
      const emptyEl = document.getElementById('dashboardAlertsEmpty');
      const badgeEl = document.getElementById('dashboardAlertsBadge');
      if (!listEl || !emptyEl || !badgeEl) return;

      try {
        const resp = await api.get('/api/alerts');
        if (!resp.ok) {
          if (resp.status === 401) window.location.href = 'signin.html';
          return;
        }
        const data = await resp.json();
        const notifications = Array.isArray(data?.alerts) ? data.alerts : [];
        const unreadCount = Number(data?.unread_count) || 0;

        // Badge
        if (unreadCount > 0) {
          badgeEl.textContent = String(unreadCount);
          badgeEl.style.display = '';
        } else {
          badgeEl.style.display = 'none';
        }

        // Render last 4 notifications as alerts (read + unread)
        listEl.innerHTML = '';
        const items = notifications;
        if (items.length === 0) {
          emptyEl.style.display = '';
          return;
        }
        emptyEl.style.display = 'none';

        for (const n of items) {
          const { cls, label } = mapTypeToSeverity(n.type);

          const card = document.createElement('div');
          card.className = `alert-card ${cls}`;

          const top = document.createElement('div');
          top.className = 'alert-top';

          const textWrap = document.createElement('div');
          textWrap.className = 'alert-text';

          const title = document.createElement('div');
          title.className = 'alert-title';
          title.textContent = n.title || 'Alert';

          const desc = document.createElement('div');
          desc.className = 'alert-desc';
          desc.textContent = n.message || '';

          textWrap.appendChild(title);
          if (desc.textContent) textWrap.appendChild(desc);
          top.appendChild(textWrap);

          const bottom = document.createElement('div');
          bottom.className = 'alert-bottom';

          const badge = document.createElement('span');
          badge.className = `alert-badge ${cls}`;
          badge.textContent = label;

          const time = document.createElement('span');
          time.className = 'alert-time';
          time.setAttribute('data-ts', n.created_at);
          time.textContent = formatRelativeTime(n.created_at);

          bottom.appendChild(badge);
          bottom.appendChild(time);

          card.appendChild(top);
          card.appendChild(bottom);
          listEl.appendChild(card);
        }

        startDashboardAlertsTimeTicker(listEl);
      } catch (e) {
        console.error('Failed to load dashboard alerts', e);
      }
    }

    // Initial load; notifications.js already polls for the bell dropdown, but
    // we keep this lightweight and only refresh once on dashboard load.
    if (typeof api !== 'undefined') {
      loadDashboardAlerts();
    }

    // Dark mode
    if (localStorage.getItem("darkMode") === "true") {
      document.body.classList.add("dark-mode");
      const darkModeBtn = document.querySelector('[aria-label="Toggle Dark Mode"]');
      if (darkModeBtn) darkModeBtn.textContent = "☀️";
    }

    // Dark Mode Toggle
    const darkModeBtn = document.querySelector('[aria-label="Toggle Dark Mode"]');
    if (darkModeBtn) {
      darkModeBtn.addEventListener("click", function () {
        document.body.classList.toggle("dark-mode");
        const isDark = document.body.classList.contains("dark-mode");
        localStorage.setItem("darkMode", isDark);
        this.textContent = isDark ? "☀️" : "🌙";
      });
    }

    // Logout
    const logoutBtn = document.querySelector(".logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async function (e) {
            e.preventDefault();
            if (await showConfirm("Are you sure you want to logout?", "Confirm Logout")) {
            localStorage.clear();
            window.location.href = "signin.html";
            }
        });
    }
});
