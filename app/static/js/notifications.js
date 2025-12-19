
// System-Wide Notifications Logic

const POLL_INTERVAL = 15000; // 15 seconds

async function fetchNotifications() {
    try {
        const resp = await api.get('/api/notifications');

        if (resp.ok) {
            const data = await resp.json();
            updateNotificationUI(data.notifications, data.unread_count);
        }
    } catch (e) {
        console.error("Failed to fetch notifications", e);
    }
}

function updateNotificationUI(notifications, unreadCount) {
    const badge = document.querySelector('.notification-badge');
    const listContainer = document.querySelector('.notification-list');
    
    // Update Badge
    if (badge) {
        if (unreadCount > 0) {
            badge.textContent = unreadCount;
            badge.style.display = 'flex';
        } else {
            badge.style.display = 'none';
        }
    }

    // Update List
    if (listContainer) {
        listContainer.innerHTML = '';
        
        if (notifications.length === 0) {
            listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #999; font-size: 13px;">No notifications</div>';
            return;
        }

        notifications.forEach(n => {
            const item = document.createElement('div');
            item.className = 'notification-item';
            if (!n.is_read) item.style.background = '#f0f7ff'; // Highlight unread
            
            // Icon color based on type
            let color = '#3498db'; // info/default
            if (n.type === 'error' || n.type === 'critical') color = '#e74c3c';
            if (n.type === 'warning') color = '#f39c12';
            if (n.type === 'success') color = '#2ecc71';

            item.innerHTML = `
                <div class="notif-title" style="color: ${color};">${n.title}</div>
                <div class="notif-desc">${n.message}</div>
                <div style="font-size: 10px; color: #bdc3c7; margin-top: 4px;">${new Date(n.created_at).toLocaleString()}</div>
            `;
            listContainer.appendChild(item);
        });
    }
}

async function markAllAsRead() {
    try {
        // Optimistic UI update: Clear immediately
        updateNotificationUI([], 0);

        await api.post('/api/notifications/mark-read');
        
        // Refresh to confirm server state
        fetchNotifications();
    } catch (e) {
        console.error("Failed to mark read", e);
    }
}

// Initial Load & Polling
document.addEventListener('DOMContentLoaded', () => {
    // Attach event listeners
    const markReadBtn = document.getElementById('mark-read-btn');
    if (markReadBtn) {
        markReadBtn.addEventListener('click', markAllAsRead);
    }
    
    const notifBtn = document.getElementById("notif-btn");
    const notifDropdown = document.getElementById("notif-dropdown");

    if (notifBtn && notifDropdown) {
      notifBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        notifDropdown.classList.toggle("active");
      });
      
      document.addEventListener("click", function (e) {
        if (notifDropdown.classList.contains("active")) {
             if (!notifDropdown.contains(e.target) && !notifBtn.contains(e.target)) {
                notifDropdown.classList.remove("active");
             }
        }
      });
    }

    // Initial Fetch
    fetchNotifications();

    // Start Polling
    setInterval(fetchNotifications, POLL_INTERVAL);
});
