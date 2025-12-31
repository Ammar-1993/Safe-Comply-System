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

        // Update chart arcs
        const circles = document.querySelectorAll('.chart-svg circle');
        if (circles.length >= 2) {
          const circumference = 342.12; // 2πr for r=80 (matches template)

          const arc1Length = circumference * (pwd / 100);
          const arc2Length = circumference * (backup / 100);

          // If both are 0, render as empty (avoid weird offsets)
          if (arc1Length === 0 && arc2Length === 0) {
            circles[0].setAttribute('stroke-dasharray', `0 ${circumference}`);
            circles[0].setAttribute('stroke-dashoffset', '0');
            circles[1].setAttribute('stroke-dasharray', `0 ${circumference}`);
            circles[1].setAttribute('stroke-dashoffset', '0');
          } else {
            circles[0].setAttribute('stroke-dasharray', `${arc1Length} ${circumference - arc1Length}`);
            circles[0].setAttribute('stroke-dashoffset', '0');

            circles[1].setAttribute('stroke-dasharray', `${arc2Length} ${circumference - arc2Length}`);
            // Start the second segment where the first ends
            circles[1].setAttribute('stroke-dashoffset', `${-arc1Length}`);
          }
        }

        // Update the percentage texts
        const labels = document.querySelectorAll('.chart-label-lg');
        if (labels.length >= 2) {
          labels[0].textContent = pwd + '%';
          labels[1].textContent = backup + '%';
        }

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
