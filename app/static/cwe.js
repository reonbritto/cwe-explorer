document.addEventListener('DOMContentLoaded', () => {
    const cweId = getParam('id');
    if (!cweId) {
        showError('No CWE ID provided. Use ?id=79');
        return;
    }

    if (!/^\d+$/.test(cweId)) {
        showError('Invalid CWE ID format. Expected numeric ID (e.g., 79).');
        return;
    }

    loadCWE(cweId);
});

async function loadCWE(cweId) {
    const loading = document.getElementById('loading');
    const content = document.getElementById('cweContent');

    try {
        const data = await fetchAPI(
            `/api/cwe/${encodeURIComponent(cweId)}`
        );

        document.getElementById('cweTitle').textContent =
            `CWE-${data.id}: ${data.name}`;
        document.title = `CWE-${data.id} - PureSecure`;
        document.getElementById('cweDescription').textContent =
            data.description;
        document.getElementById('mitreLink').href =
            `https://cwe.mitre.org/data/definitions/${encodeURIComponent(data.id)}.html`;

        loading.style.display = 'none';
        content.style.display = 'block';

        loadAssociatedCVEs(cweId);
    } catch (err) {
        showError(
            `Failed to load CWE-${escapeHTML(cweId)}: ` +
            escapeHTML(err.message)
        );
    }
}

async function loadAssociatedCVEs(cweId) {
    const loading2 = document.getElementById('loading2');
    const cvesList = document.getElementById('cvesList');

    try {
        const data = await fetchAPI(
            `/api/cwe/${encodeURIComponent(cweId)}/cves`
        );
        loading2.style.display = 'none';

        if (data.length === 0) {
            cvesList.innerHTML =
                '<p style="color:var(--text-secondary)">' +
                'No CVEs found for this CWE.</p>';
            return;
        }

        let html = '<table class="data-table"><thead><tr>';
        html += '<th>CVE ID</th><th>Severity</th><th>Score</th>';
        html += '<th>Published</th><th>Description</th>';
        html += '</tr></thead><tbody>';

        data.forEach(cve => {
            const badge = cve.severity
                ? severityBadge(cve.cvss_v3, cve.severity)
                : '<span style="color:var(--text-secondary)">N/A</span>';
            const score = cve.cvss_v3 !== null
                ? cve.cvss_v3.toFixed(1) : 'N/A';

            html += `<tr class="card-clickable"
                         onclick="goToCVE('${escapeHTML(cve.cve_id)}')">
                <td><strong style="color:var(--accent-blue)">
                    ${escapeHTML(cve.cve_id)}</strong></td>
                <td>${badge}</td>
                <td>${score}</td>
                <td>${formatDate(cve.published)}</td>
                <td style="max-width:400px; overflow:hidden;
                    text-overflow:ellipsis; white-space:nowrap;">
                    ${escapeHTML(cve.description)}</td>
            </tr>`;
        });

        html += '</tbody></table>';
        cvesList.innerHTML = html;
    } catch (err) {
        loading2.style.display = 'none';
        cvesList.innerHTML =
            `<p class="error-message">Failed to load CVEs: ` +
            `${escapeHTML(err.message)}</p>`;
    }
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
