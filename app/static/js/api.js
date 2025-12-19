/**
 * Centralized API Utility
 * Handles base URLs, Authentication headers, and common request logic.
 */

class ApiClient {
    constructor() {
        // Base URL is empty for relative paths, or can be configured
        this.baseUrl = ''; 
    }

    /**
     * Get headers with Auth token
     * @param {string|null} contentType - Content-Type header value. Pass null for FormData.
     */
    getHeaders(contentType = 'application/json') {
        const headers = {};
        if (contentType) {
            headers['Content-Type'] = contentType;
        }
        
        // Support both token keys used in the app
        const token = localStorage.getItem('access_token') || localStorage.getItem('authToken');
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        return headers;
    }

    /**
     * Generic request method
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        // Prepare headers
        const defaultHeaders = this.getHeaders(options.contentType !== undefined ? options.contentType : 'application/json');
        const config = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, config);
            
            // Global 401 handling
            if (response.status === 401) {
                console.warn('Unauthorized access. Token might be expired.');
                // Optional: Trigger a global event or redirect
                // window.location.href = 'signin.html';
            }

            return response;
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    upload(endpoint, formData) {
        return this.request(endpoint, {
            method: 'POST',
            body: formData,
            contentType: null // Let browser set Content-Type with boundary
        });
    }
}

// Export a singleton instance
const api = new ApiClient();
