/**
 * Shared utilities for PureSecure CWE Explorer.
 * XSS prevention, authenticated fetch wrappers, and UI helpers.
 */

// Prevent XSS by escaping HTML special characters
function escapeHTML(str) {
    if (!str) return '';
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// ═══════════════ THEME TOGGLE ═══════════════
function initThemeToggle() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    const btn = document.createElement('button');
    btn.className = 'theme-toggle';
    btn.setAttribute('aria-label', 'Toggle Dark Mode');
    
    // Default to light if nothing is in localstorage
    const currentTheme = localStorage.getItem('theme');
    if (currentTheme === 'dark') {
        document.documentElement.classList.add('dark-theme');
    }

    const updateIcon = () => {
        const isDark = document.documentElement.classList.contains('dark-theme');
        btn.innerHTML = isDark 
            ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>` 
            : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
    };

    btn.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark-theme');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateIcon();
    });

    updateIcon();
    
    // Inject at the end of nav if it exists, otherwise end of navbar
    const nav = navbar.querySelector('nav');
    if (nav) {
        btn.style.marginLeft = '0.5rem';
        nav.appendChild(btn);
    } else {
        navbar.appendChild(btn);
    }
}

// Ensure theme toggle is created as soon as DOM is ready
document.addEventListener('DOMContentLoaded', initThemeToggle);

// Authenticated wrapper around fetch — attaches Entra ID Bearer token
async function fetchAPI(url) {
    const token = await getToken();
    if (!token) return null;  // login redirect in progress

    const response = await fetch(url, {
        headers: { "Authorization": "Bearer " + token }
    });

    if (response.status === 401) {
        // Token expired or invalid — redirect to login
        window.location.href = "/login.html";
        return null;
    }
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

// Render suggestion dropdown items from API data
function renderSuggestions(data) {
    return data.map(item => {
        const icon = item.type === 'cwe'
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`;
        if (item.action) {
            return `<a href="${escapeHTML(item.action)}" class="suggestion-item">${icon}<span>${escapeHTML(item.text)}</span><span class="suggestion-type">${escapeHTML(item.type)}</span></a>`;
        }
        return `<div class="suggestion-item suggestion-tip">${icon}<span>${escapeHTML(item.text)}</span></div>`;
    }).join('');
}

// Create a CWE card element for the homepage and search results
function createCWECard(cwe, index) {
    const card = document.createElement('div');
    card.className = 'cwe-card';
    card.style.animationDelay = `${index * 0.03}s`;

    const cweId = escapeHTML(cwe.id);
    const cweName = escapeHTML(cwe.name);
    const desc = escapeHTML(
        cwe.description
            ? (cwe.description.length > 200
                ? cwe.description.substring(0, 200) + '...'
                : cwe.description)
            : 'No description available'
    );

    // Show relationship count if available
    const relCount = (cwe.related_weaknesses || []).length;
    const relBadge = relCount > 0
        ? `<span class="cwe-rel-count">${relCount} related</span>`
        : '';

    card.innerHTML = `
        <div class="cwe-card-accent"></div>
        <div class="cwe-card-body">
            <div class="cwe-card-header">
                <span class="cwe-card-id">CWE-${cweId}</span>
                <span class="cwe-card-name">${cweName}</span>
            </div>
            <div class="cwe-card-desc">${desc}</div>
            <div class="cwe-card-meta">
                ${relBadge}
            </div>
        </div>
    `;

    card.addEventListener('click', () => goToCWE(cwe.id));
    return card;
}

/**
 * Populate monitoring-service links in the navbar from /api/services.
 * Uses data-service attributes to match links to their URLs.
 */
async function loadServiceLinks() {
    try {
        var resp = await fetch("/api/services");
        var urls = await resp.json();
        document.querySelectorAll('[data-service]').forEach(function (el) {
            var key = el.getAttribute('data-service');
            if (urls[key]) {
                // For Grafana, preserve any path suffix already in the href
                // (e.g. /d/cwe-explorer-api) — only replace the origin/base.
                if (key === 'grafana') {
                    var suffix = el.getAttribute('data-service-path') || '/d/cwe-explorer-api';
                    el.href = urls[key].replace(/\/$/, '') + suffix;
                } else {
                    el.href = urls[key];
                }
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        });
    } catch (e) {
        // keep default href values on error
    }
}

/**
 * Initialise auth guard — call this at the top of every protected page.
 * Ensures the user is signed in before the page loads.
 * Adds user info + logout button to the navbar.
 */
async function requireAuth() {
    const ok = await initAuth();
    if (!ok) {
        window.location.href = "/login.html";
        return false;
    }

    const user = getCurrentUser();
    if (!user) {
        // Not signed in — show login page instead of auto-redirecting
        window.location.href = "/login.html";
        return false;
    }

    // Add user info to navbar
    const nav = document.querySelector('.navbar nav');
    if (nav) {
        const userSpan = document.createElement('span');
        userSpan.className = 'nav-user';
        userSpan.innerHTML = `
            <span class="nav-user-name">${escapeHTML(user.name)}</span>
            <button onclick="logout()" class="nav-logout">Sign Out</button>
        `;
        nav.appendChild(userSpan);
    }

    return true;
}
