/**
 * Shared utilities for PureSecure CVE Explorer.
 * XSS prevention, fetch wrappers, and UI helpers.
 */

// Prevent XSS by escaping HTML special characters
function escapeHTML(str) {
    if (!str) return '';
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// Wrapper around fetch with error handling
async function fetchAPI(url) {
    const response = await fetch(url);
    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `API error: ${response.status}`);
    }
    return response.json();
}

// Format ISO date string to readable format
function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const d = new Date(isoString);
    return d.toLocaleDateString('en-GB', {
        year: 'numeric', month: 'short', day: 'numeric'
    });
}

// Get CSS class for severity level
function severityClass(severity) {
    if (!severity) return 'severity-unknown';
    switch (severity.toUpperCase()) {
        case 'CRITICAL': return 'severity-critical';
        case 'HIGH': return 'severity-high';
        case 'MEDIUM': return 'severity-medium';
        case 'LOW': return 'severity-low';
        default: return 'severity-unknown';
    }
}

// Create severity badge HTML
function severityBadge(score, severity) {
    const cls = severityClass(severity);
    const label = severity ? escapeHTML(severity) : 'N/A';
    const scoreText = score !== null && score !== undefined
        ? score.toFixed(1) : '?';
    return `<span class="badge ${cls}">${scoreText} ${label}</span>`;
}

// Get URL parameters
function getParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
}

// Navigate to CVE detail page
function goToCVE(cveId) {
    window.location.href =
        `/cve.html?id=${encodeURIComponent(cveId)}`;
}

// Navigate to CWE detail page
function goToCWE(cweId) {
    window.location.href =
        `/cwe.html?id=${encodeURIComponent(cweId)}`;
}

// Navigate to search page
function goToSearch(query) {
    window.location.href =
        `/search.html?keyword=${encodeURIComponent(query)}`;
}
