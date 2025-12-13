/**
 * SafeComply Custom Modal System
 * Modern, beautiful dialogs to replace native alerts
 */

// Modal container (will be created dynamically)
let scModalContainer = null;

/**
 * Initialize the modal container
 */
function initModalContainer() {
  if (scModalContainer) return;
  
  scModalContainer = document.createElement('div');
  scModalContainer.id = 'sc-modal-container';
  document.body.appendChild(scModalContainer);
}

/**
 * Get icon for modal type
 */
function getModalIcon(type) {
  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
    confirm: '?'
  };
  return icons[type] || icons.info;
}

/**
 * Get title for modal type
 */
function getModalTitle(type, customTitle) {
  if (customTitle) return customTitle;
  const titles = {
    success: 'Success!',
    error: 'Error',
    warning: 'Warning',
    info: 'Information',
    confirm: 'Confirm'
  };
  return titles[type] || 'Notice';
}

/**
 * Show a custom modal
 * @param {Object} options - Modal options
 * @param {string} options.type - 'success', 'error', 'warning', 'info', 'confirm'
 * @param {string} options.title - Custom title (optional)
 * @param {string} options.message - Modal message
 * @param {boolean} options.showCancel - Show cancel button (default: false)
 * @param {string} options.confirmText - Confirm button text (default: 'OK')
 * @param {string} options.cancelText - Cancel button text (default: 'Cancel')
 * @param {string} options.confirmClass - Button class: 'primary', 'success', 'danger' (default: 'primary')
 * @returns {Promise<boolean>} - Resolves true if confirmed, false if cancelled
 */
function showModal(options) {
  initModalContainer();
  
  return new Promise((resolve) => {
    const {
      type = 'info',
      title,
      message = '',
      showCancel = false,
      confirmText = 'OK',
      cancelText = 'Cancel',
      confirmClass = 'primary'
    } = options;
    
    const modalId = 'sc-modal-' + Date.now();
    
    const modalHTML = `
      <div class="sc-modal-overlay" id="${modalId}">
        <div class="sc-modal">
          <div class="sc-modal-header">
            <div class="sc-modal-icon ${type}">${getModalIcon(type)}</div>
            <h3 class="sc-modal-title">${getModalTitle(type, title)}</h3>
          </div>
          <div class="sc-modal-body">
            <p class="sc-modal-message">${message}</p>
          </div>
          <div class="sc-modal-footer">
            ${showCancel ? `<button class="sc-modal-btn secondary" data-action="cancel">${cancelText}</button>` : ''}
            <button class="sc-modal-btn ${confirmClass}" data-action="confirm">${confirmText}</button>
          </div>
        </div>
      </div>
    `;
    
    scModalContainer.insertAdjacentHTML('beforeend', modalHTML);
    const overlay = document.getElementById(modalId);
    
    // Trigger animation
    requestAnimationFrame(() => {
      overlay.classList.add('active');
    });
    
    // Handle button clicks
    const handleClick = (e) => {
      const action = e.target.dataset.action;
      if (action) {
        closeModal(overlay);
        resolve(action === 'confirm');
      }
    };
    
    overlay.addEventListener('click', (e) => {
      // Close on overlay click (not on modal content)
      if (e.target === overlay && showCancel) {
        closeModal(overlay);
        resolve(false);
      }
    });
    
    overlay.querySelector('.sc-modal-footer').addEventListener('click', handleClick);
    
    // Handle escape key
    const handleKeydown = (e) => {
      if (e.key === 'Escape' && showCancel) {
        closeModal(overlay);
        resolve(false);
        document.removeEventListener('keydown', handleKeydown);
      } else if (e.key === 'Enter') {
        closeModal(overlay);
        resolve(true);
        document.removeEventListener('keydown', handleKeydown);
      }
    };
    document.addEventListener('keydown', handleKeydown);
  });
}

/**
 * Close and remove a modal
 */
function closeModal(overlay) {
  overlay.classList.remove('active');
  setTimeout(() => {
    overlay.remove();
  }, 300);
}

// ============ Convenience Functions ============

/**
 * Show a success message
 */
function showSuccess(message, title) {
  return showModal({ type: 'success', message, title, confirmClass: 'success' });
}

/**
 * Show an error message
 */
function showError(message, title) {
  return showModal({ type: 'error', message, title, confirmClass: 'danger' });
}

/**
 * Show a warning message
 */
function showWarning(message, title) {
  return showModal({ type: 'warning', message, title });
}

/**
 * Show an info message
 */
function showInfo(message, title) {
  return showModal({ type: 'info', message, title });
}

/**
 * Show a confirmation dialog
 * @returns {Promise<boolean>} - true if confirmed, false if cancelled
 */
function showConfirm(message, title) {
  return showModal({
    type: 'confirm',
    message,
    title: title || 'Confirm Action',
    showCancel: true,
    confirmText: 'Yes',
    cancelText: 'No'
  });
}

/**
 * Show a dangerous action confirmation (red confirm button)
 */
function showDangerConfirm(message, title) {
  return showModal({
    type: 'warning',
    message,
    title: title || 'Are you sure?',
    showCancel: true,
    confirmText: 'Delete',
    cancelText: 'Cancel',
    confirmClass: 'danger'
  });
}
