document.addEventListener('DOMContentLoaded', () => {
    const cveId = getParam('id');
    if (!cveId) {
        showError('No CVE ID provided. Use ?id=CVE-YYYY-NNNNN');
        return;
    }

    if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
        showError('Invalid CVE ID format. Expected: CVE-YYYY-NNNNN');
        return;
    }

    loadCVE(cveId.toUpperCase());
});

async function loadCVE(cveId) {
    const loading = document.getElementById('loading');
    const content = document.getElementById('cveContent');

    try {
        const data = await fetchAPI(
            `/api/cve/${encodeURIComponent(cveId)}`
        );

        document.getElementById('cveId').textContent = data.cve_id;
        document.title = `${data.cve_id} - PureSecure`;
        document.getElementById('severityBadge').innerHTML =
            severityBadge(data.cvss.v3_score, data.cvss.v3_severity);
        document.getElementById('published').textContent =
            formatDate(data.published);
        document.getElementById('modified').textContent =
            formatDate(data.modified);

        document.getElementById('description').textContent =
            data.description;

        renderCVSS(data.cvss);
        renderCWEs(data.cwe_ids);
        renderProducts(data.affected_products);
        renderReferences(data.references);

        loading.style.display = 'none';
        content.style.display = 'block';
    } catch (err) {
        showError(
            `Failed to load ${escapeHTML(cveId)}: ${escapeHTML(err.message)}`
        );
    }
}

function renderCVSS(cvss) {
    const panel = document.getElementById('cvssPanel');
    let html = '';

    if (cvss.v3_score !== null && cvss.v3_score !== undefined) {
        const color = getScoreColor(cvss.v3_score);
        html += `<div class="cvss-box">
            <h3>CVSS v3.1</h3>
            <div class="cvss-score" style="color:${color}">
                ${cvss.v3_score.toFixed(1)}
            </div>
            <div class="score-bar">
                <div class="score-bar-fill"
                     style="width:${cvss.v3_score * 10}%;
                            background:${color}"></div>
            </div>
            ${cvss.v3_vector
                ? `<div class="cvss-vector">${escapeHTML(cvss.v3_vector)}</div>`
                : ''}
            ${cvss.v3_severity
                ? `<div style="margin-top:0.5rem;">
                    ${severityBadge(cvss.v3_score, cvss.v3_severity)}
                   </div>`
                : ''}
        </div>`;
    }

    if (cvss.v2_score !== null && cvss.v2_score !== undefined) {
        const color = getScoreColor(cvss.v2_score);
        html += `<div class="cvss-box">
            <h3>CVSS v2.0</h3>
            <div class="cvss-score" style="color:${color}">
                ${cvss.v2_score.toFixed(1)}
            </div>
            <div class="score-bar">
                <div class="score-bar-fill"
                     style="width:${cvss.v2_score * 10}%;
                            background:${color}"></div>
            </div>
            ${cvss.v2_vector
                ? `<div class="cvss-vector">${escapeHTML(cvss.v2_vector)}</div>`
                : ''}
        </div>`;
    }

    if (!html) {
        html = '<p style="color:var(--text-secondary)">' +
               'No CVSS scores available.</p>';
    }
    panel.innerHTML = html;
}

function renderCWEs(cweIds) {
    const section = document.getElementById('cweSection');
    if (!cweIds || cweIds.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No CWE classification available.</p>';
        return;
    }

    section.innerHTML = cweIds.map(cwe => {
        const num = cwe.replace('CWE-', '');
        return `<span class="cwe-tag"
                      onclick="goToCWE('${escapeHTML(num)}')"
                >${escapeHTML(cwe)}</span>`;
    }).join('');
}

function renderProducts(products) {
    const section = document.getElementById('productsSection');
    if (!products || products.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No affected product data available.</p>';
        return;
    }

    const seen = new Set();
    const unique = products.filter(p => {
        const key = `${p.vendor}|${p.product}|${p.version}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).slice(0, 50);

    let html = '<table class="data-table"><thead><tr>';
    html += '<th>Vendor</th><th>Product</th><th>Version</th>';
    html += '</tr></thead><tbody>';

    unique.forEach(p => {
        html += `<tr>
            <td>${escapeHTML(p.vendor)}</td>
            <td>${escapeHTML(p.product)}</td>
            <td>${escapeHTML(p.version)}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    section.innerHTML = html;
}

function renderReferences(references) {
    const section = document.getElementById('referencesSection');
    if (!references || references.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No references available.</p>';
        return;
    }

    let html = '<ul class="ref-list">';
    references.forEach(ref => {
        const tags = (ref.tags || []).map(t =>
            `<span class="ref-tag">${escapeHTML(t)}</span>`
        ).join('');
        html += `<li>
            <a href="${escapeHTML(ref.url)}" target="_blank"
               rel="noopener noreferrer">${escapeHTML(ref.url)}</a>
            ${tags}
        </li>`;
    });
    html += '</ul>';
    section.innerHTML = html;
}

function getScoreColor(score) {
    if (score >= 9.0) return 'var(--severity-critical)';
    if (score >= 7.0) return 'var(--severity-high)';
    if (score >= 4.0) return 'var(--severity-medium)';
    return 'var(--severity-low)';
}

function showError(message) {
    document.getElementById('loading').style.display = 'none';
    const errorDiv = document.getElementById('errorDiv');
    errorDiv.style.display = 'block';
    errorDiv.innerHTML = `<p>${escapeHTML(message)}</p>
        <p style="margin-top:1rem;">
            <a href="/" style="color:var(--accent-blue);">
                Return to Home
            </a>
        </p>`;
}
