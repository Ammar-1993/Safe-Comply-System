document.addEventListener('DOMContentLoaded', () => {
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

        // Update Pie Chart Data (Visual only for now, text update)
        // const pwd = data.policy_breakdown.password;
        // const backup = data.policy_breakdown.backup;

        // Update the central percentage to average compliance.
        // EDITED: Updated selector to match new CSS class instead of inline style
        const centerText = document.querySelector('.chart-label-lg');
        if (centerText) centerText.textContent = data.compliance_rate + '%';

      } catch (e) {
        console.error('Failed to load stats', e);
      }
    }

    loadDashboardStats();

    // Dark mode
    if (localStorage.getItem("darkMode") === "true") {
      document.body.classList.add("dark-mode");
      const moonBtn = document.querySelectorAll(".icon-btn")[1];
      if (moonBtn) moonBtn.textContent = "☀️";
    }

    const moonBtns = document.querySelectorAll(".icon-btn");
    
    // Dark Mode Toggle
    if (moonBtns[1]) {
      moonBtns[1].addEventListener("click", function () {
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
