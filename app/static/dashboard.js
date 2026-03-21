document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const suggestionsDiv = document.getElementById('suggestions');

    let debounceTimer = null;

    // Search handlers
    searchBtn.addEventListener('click', handleSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            suggestionsDiv.classList.remove('active');
            handleSearch();
        }
    });

    // Live suggestions as user types
    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const q = searchInput.value.trim();
        if (q.length < 2) {
            suggestionsDiv.classList.remove('active');
            return;
        }
        debounceTimer = setTimeout(() => fetchSuggestions(q), 250);
    });

    // Close suggestions on outside click
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.hero-search')) {
            suggestionsDiv.classList.remove('active');
        }
    });

    function handleSearch() {
        const q = searchInput.value.trim();
        if (!q) return;
        if (/^CVE-\d{4}-\d{4,}$/i.test(q)) {
            goToCVE(q.toUpperCase());
        } else {
            goToSearch(q);
        }
    }

    async function fetchSuggestions(q) {
        try {
            const data = await fetchAPI(
                `/api/cve/suggestions?q=${encodeURIComponent(q)}`
            );
            if (data.length === 0) {
                suggestionsDiv.classList.remove('active');
                return;
            }

            suggestionsDiv.innerHTML = data.map(item => {
                const icon = item.type === 'cwe'
                    ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
                    : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`;

                if (item.action) {
                    return `<a href="${escapeHTML(item.action)}" class="suggestion-item">
                        ${icon}
                        <span>${escapeHTML(item.text)}</span>
                        <span class="suggestion-type">${escapeHTML(item.type)}</span>
                    </a>`;
                }
                return `<div class="suggestion-item suggestion-tip">
                    ${icon}
                    <span>${escapeHTML(item.text)}</span>
                </div>`;
            }).join('');

            suggestionsDiv.classList.add('active');
        } catch (err) {
            suggestionsDiv.classList.remove('active');
        }
    }

    // Load page data
    loadLatestCVEs();
});

async function loadLatestCVEs() {
    const container = document.getElementById('latestCves');
    const loading = document.getElementById('latestLoading');

    try {
        const data = await fetchAPI('/api/cve/latest?limit=20');
        loading.style.display = 'none';

        if (data.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <p>No CVE data loaded yet.</p>
                <p class="subtext">Try searching for a specific CVE like
                <a href="/cve.html?id=CVE-2021-44228"
                   style="color:var(--green-dark)">CVE-2021-44228</a>
                to start populating the database.</p>
            </div>`;
            return;
        }

        data.forEach((cve, index) => {
            const card = document.createElement('div');
            card.className = 'cve-card';
            card.style.animationDelay = `${index * 0.03}s`;

            const sevClass = severityClass(cve.severity);

            const badge = cve.cvss_v3 !== null && cve.cvss_v3 !== undefined
                ? severityBadge(cve.cvss_v3, cve.severity)
                : '<span class="badge severity-unknown">N/A</span>';

            card.innerHTML = `
                <div class="cve-card-severity ${sevClass}"></div>
                <div class="cve-card-body">
                    <div class="cve-card-title">
                        ${escapeHTML(cve.description || 'No description available')}
                    </div>
                    <div class="cve-card-meta">
                        <span class="cve-card-id">${escapeHTML(cve.cve_id)}</span>
                        ${badge}
                        <span class="cve-card-date">${formatDate(cve.published)}</span>
                    </div>
                </div>
            `;

            card.addEventListener('click', () => goToCVE(cve.cve_id));
            container.appendChild(card);
        });
    } catch (err) {
        loading.style.display = 'none';
        container.innerHTML = `<div class="empty-state">
            <p>Could not load latest CVEs.</p>
            <p class="subtext">${escapeHTML(err.message)}</p>
        </div>`;
    }
}
