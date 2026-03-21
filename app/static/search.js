document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const severityFilter = document.getElementById('severityFilter');
    const resultsDiv = document.getElementById('results');
    const loadingDiv = document.getElementById('loading');
    const paginationDiv = document.getElementById('pagination');
    const recommendationsDiv = document.getElementById('recommendations');
    const resultsHeader = document.getElementById('resultsHeader');
    const suggestionsDiv = document.getElementById('suggestions');

    let currentOffset = 0;
    const PAGE_SIZE = 20;
    let debounceTimer = null;

    // Pre-fill from URL params
    const urlKeyword = getParam('keyword');
    if (urlKeyword) {
        searchInput.value = urlKeyword;
        performSearch();
    }

    searchBtn.addEventListener('click', () => {
        currentOffset = 0;
        performSearch();
    });

    // Auto-search when severity filter changes
    severityFilter.addEventListener('change', () => {
        currentOffset = 0;
        performSearch();
    });

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            currentOffset = 0;
            suggestionsDiv.classList.remove('active');
            const q = searchInput.value.trim();
            if (/^CVE-\d{4}-\d{4,}$/i.test(q)) {
                goToCVE(q.toUpperCase());
            } else {
                performSearch();
            }
        }
    });

    // Live suggestions
    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const q = searchInput.value.trim();
        if (q.length < 2) {
            suggestionsDiv.classList.remove('active');
            return;
        }
        debounceTimer = setTimeout(() => fetchSuggestions(q), 250);
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.search-wrapper')) {
            suggestionsDiv.classList.remove('active');
        }
    });

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
                    return `<a href="${escapeHTML(item.action)}" class="suggestion-item">${icon}<span>${escapeHTML(item.text)}</span><span class="suggestion-type">${escapeHTML(item.type)}</span></a>`;
                }
                return `<div class="suggestion-item suggestion-tip">${icon}<span>${escapeHTML(item.text)}</span></div>`;
            }).join('');
            suggestionsDiv.classList.add('active');
        } catch (err) {
            suggestionsDiv.classList.remove('active');
        }
    }

    async function performSearch() {
        const keyword = searchInput.value.trim();
        const severity = severityFilter.value;

        if (!keyword && !severity) return;

        recommendationsDiv.style.display = 'none';
        loadingDiv.classList.remove('hidden');
        resultsDiv.innerHTML = '';
        paginationDiv.innerHTML = '';
        resultsHeader.style.display = 'none';

        try {
            let url = `/api/cve/search?limit=${PAGE_SIZE}` +
                      `&offset=${currentOffset}`;
            if (keyword) {
                url += `&keyword=${encodeURIComponent(keyword)}`;
            }
            if (severity) {
                url += `&severity=${encodeURIComponent(severity)}`;
            }

            const data = await fetchAPI(url);
            displayResults(data);
        } catch (err) {
            resultsDiv.innerHTML = `<div class="empty-state">
                <p>Search failed: ${escapeHTML(err.message)}</p>
                <p class="subtext">The NVD API may be rate-limited.
                Please wait a moment and try again.</p>
            </div>`;
        } finally {
            loadingDiv.classList.add('hidden');
        }
    }

    function displayResults(data) {
        if (data.length === 0) {
            resultsDiv.innerHTML = `<div class="empty-state">
                <p>No vulnerabilities found matching your criteria.</p>
                <p class="subtext">Try different keywords or broaden
                your filters.</p>
            </div>`;
            return;
        }

        resultsHeader.style.display = 'block';
        document.getElementById('resultsCount').textContent =
            `Showing ${currentOffset + 1}\u2013${currentOffset + data.length} results`;

        data.forEach((cve, index) => {
            const card = document.createElement('div');
            card.className = 'cve-card';
            card.style.animationDelay = `${index * 0.03}s`;

            const sevClass = severityClass(cve.severity);

            const badge = cve.cvss_v3 !== null
                    && cve.cvss_v3 !== undefined
                ? severityBadge(cve.cvss_v3, cve.severity)
                : '<span class="badge severity-unknown">N/A</span>';

            card.innerHTML = `
                <div class="cve-card-severity ${sevClass}"></div>
                <div class="cve-card-body">
                    <div class="cve-card-title">
                        ${escapeHTML(cve.description
                            || 'No description available')}
                    </div>
                    <div class="cve-card-meta">
                        <span class="cve-card-id">
                            ${escapeHTML(cve.cve_id)}</span>
                        ${badge}
                        <span class="cve-card-date">
                            ${formatDate(cve.published)}</span>
                    </div>
                </div>
            `;

            card.addEventListener('click', () => goToCVE(cve.cve_id));
            resultsDiv.appendChild(card);
        });

        // Pagination
        if (data.length >= PAGE_SIZE || currentOffset > 0) {
            let pHtml = '';
            if (currentOffset > 0) {
                pHtml += '<button id="prevPage">&larr; Previous</button>';
            }
            if (data.length >= PAGE_SIZE) {
                pHtml += '<button id="nextPage">Next &rarr;</button>';
            }
            paginationDiv.innerHTML = pHtml;

            const prevBtn = document.getElementById('prevPage');
            const nextBtn = document.getElementById('nextPage');
            if (prevBtn) {
                prevBtn.addEventListener('click', () => {
                    currentOffset = Math.max(
                        0, currentOffset - PAGE_SIZE
                    );
                    performSearch();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                });
            }
            if (nextBtn) {
                nextBtn.addEventListener('click', () => {
                    currentOffset += PAGE_SIZE;
                    performSearch();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                });
            }
        }
    }
});
