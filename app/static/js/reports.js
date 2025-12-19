// Pagination State
let allReports = [];
let currentPage = 1;
const itemsPerPage = 10;

// Helper function to download files with auth header
async function downloadReportFile(reportId, type) {
    const endpoint = `/api/reports/${reportId}/${type}`;
    try {
        const res = await api.get(endpoint);

        if (!res.ok) {
            const err = await res.json();
            showError('Download failed: ' + (err.error || res.statusText), 'Download Error');
            return;
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        // Try to get filename from Content-Disposition header if available, else default
        const contentDisposition = res.headers.get('Content-Disposition');
        let filename = `report_${reportId}.${type === 'excel' ? 'xlsx' : 'pdf'}`;
        if (contentDisposition) {
            const match = contentDisposition.match(/filename="?([^"]+)"?/);
            if (match && match[1]) filename = match[1];
        }
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (e) {
        console.error('Download error:', e);
        showError('An error occurred while downloading the file.', 'System Error');
    }
}

async function deleteReport(reportId) {
    if (!await showDangerConfirm('Are you sure you want to delete this report? This action cannot be undone.', 'Delete Report')) {
        return;
    }

    try {
        const res = await api.delete(`/reports/${reportId}`);

        if (res.ok) {
            // Refresh the table
            loadReportsArchive();
            // Also clear the current report view if it was the deleted one
            if (window.currentReportId == reportId) {
                 const reportSection = document.getElementById("reportSection");
                 const uploadSection = document.getElementById("uploadSection");
                 if (reportSection) reportSection.classList.remove("show");
                 if (uploadSection) uploadSection.style.display = "block";
                 window.currentReportId = null;
            }
            showSuccess('Report deleted successfully', 'Deleted');
        } else {
            const err = await res.json();
            showError('Failed to delete report: ' + (err.error || res.statusText), 'Delete Failed');
        }
    } catch (e) {
        console.error('Delete error:', e);
        showError('An error occurred while deleting the report.', 'System Error');
    }
}

// Function exposed globally so it can be called from HTML or other scripts
async function loadReportsArchive() {
    console.log("Loading reports archive...");
    try {
        const res = await api.get('/reports');

        if (!res.ok) {
            console.warn('Failed to fetch reports:', res.status);
            if(res.status === 401) {
                // Optional: Handle token expiration
            }
            return;
        }

        const data = await res.json();
        allReports = data.reports || [];
        
        // Sort rows by ID descending (newest first) if not already sorted
        allReports.sort((a, b) => b.id - a.id);

        renderTable(1);

    } catch (e) {
        console.error('Error rendering reports:', e);
    }
}

function renderTable(page) {
    currentPage = page;
    const tbody = document.querySelector('#reportsTable tbody');
    const empty = document.getElementById('reportsEmpty');
    const table = document.getElementById('reportsTable');
    const paginationControls = document.getElementById('paginationControls');

    if (!tbody) return;

    tbody.innerHTML = ''; // Clear existing rows

    if (allReports.length === 0) {
        if (empty) empty.style.display = 'block';
        if (table) table.style.display = 'none';
        if (paginationControls) paginationControls.style.display = 'none';
        return;
    }

    // Hide empty state, show table
    if (empty) empty.style.display = 'none';
    if (table) table.style.display = 'table';
    if (paginationControls) paginationControls.style.display = 'flex';

    const start = (page - 1) * itemsPerPage;
    const end = start + itemsPerPage;
    const pageItems = allReports.slice(start, end);

    pageItems.forEach(r => {
        const tr = document.createElement('tr');
        
        // Format Date
        let dateStr = r.uploaded_at;
        try {
            const dateObj = new Date(r.uploaded_at);
            dateStr = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        } catch(e) {}

        // Calculate Score Color
        let scoreClass = 'danger';
        if (r.overall_score >= 80) scoreClass = 'success';
        else if (r.overall_score >= 50) scoreClass = 'warning';

        tr.innerHTML = `
            <td>#${r.id}</td>
            <td>
                <div style="font-weight:500;">${r.filename}</div>
                <div style="font-size:11px; color:#999;">${r.total} records</div>
            </td>
            <td>${r.uploaded_by || 'Unknown'}</td>
            <td>${dateStr}</td>
            <td>
                <span class="score-badge ${scoreClass}">
                    ${r.overall_score}%
                </span>
            </td>
            <td>
                <a href="compliance-report-view.html?id=${r.id}" class="action-link">
                    🔍 View
                </a>
                <a href="#" onclick="deleteReport(${r.id}); return false;" class="action-link" style="color: #e74c3c;">
                    🗑️ Delete
                </a>
                <a href="#" onclick="downloadReportFile(${r.id}, 'excel'); return false;" class="action-link">
                    📊 Excel
                </a>
                <a href="#" onclick="downloadReportFile(${r.id}, 'pdf'); return false;" class="action-link">
                    📄 PDF
                </a>
            </td>`;
        tbody.appendChild(tr);
    });

    renderPagination();
}

function renderPagination() {
    const paginationControls = document.getElementById('paginationControls');
    if (!paginationControls) return;

    paginationControls.innerHTML = '';
    const totalPages = Math.ceil(allReports.length / itemsPerPage);

    if (totalPages <= 1) return;

    // Prev Button
    const prevBtn = document.createElement('button');
    prevBtn.className = 'pagination-btn';
    prevBtn.textContent = '«';
    prevBtn.disabled = currentPage === 1;
    prevBtn.onclick = () => renderTable(currentPage - 1);
    paginationControls.appendChild(prevBtn);

    // Page Numbers
    // Simple logic: show all if <= 7, else show start, end, and current neighborhood
    // For simplicity in this iteration, let's show a max of 5 buttons around current
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    
    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }

    for (let i = startPage; i <= endPage; i++) {
        const btn = document.createElement('button');
        btn.className = `pagination-btn ${i === currentPage ? 'active' : ''}`;
        btn.textContent = i;
        btn.onclick = () => renderTable(i);
        paginationControls.appendChild(btn);
    }

    // Next Button
    const nextBtn = document.createElement('button');
    nextBtn.className = 'pagination-btn';
    nextBtn.textContent = '»';
    nextBtn.disabled = currentPage === totalPages;
    nextBtn.onclick = () => renderTable(currentPage + 1);
    paginationControls.appendChild(nextBtn);
}

// Auto-load on page ready
document.addEventListener('DOMContentLoaded', loadReportsArchive);