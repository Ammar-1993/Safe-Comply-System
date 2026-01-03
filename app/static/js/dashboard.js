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
