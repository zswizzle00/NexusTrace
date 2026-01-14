/**
 * NexusTrace - Main JavaScript
 * Version: 2.0 (Refactored)
 */

// =============================================================================
// Configuration
// =============================================================================
const CONFIG = {
    // Score thresholds for color coding
    SCORE_THRESHOLDS: {
        HIGH: 75,
        MEDIUM: 25
    },
    // Keys that indicate "present" data (show as green)
    PRESENT_KEYS: [
        'country', 'country code', 'country_name', 'countrycode', 'region',
        'regioncode', 'city', 'organization', 'organisation', 'org', 'provider',
        'asn', 'hostname', 'name', 'symbol', 'type', 'range', 'address',
        'postcode', 'timezone', 'continent', 'continentcode', 'currency',
        'code', 'iso', 'isocode', 'latitude', 'longitude'
    ],
    // Fields to exclude from ProxyCheck display
    PROXYCHECK_EXCLUDE: [
        'currency', 'devices', 'isocode', 'continent', 'continentcode',
        'regioncode', 'organisation', 'latitude', 'longitude', 'postcode'
    ],
    // Fields to exclude from AlienVault general section
    ALIENVAULT_GENERAL_EXCLUDE: [
        'accuracy_radius', 'area_code', 'base_indicator', 'charset', 'city_data',
        'continent_code', 'country_code2', 'country_code3', 'dma_code', 'false_positive',
        'flag_title', 'flag_url', 'latitude', 'longitude', 'pulse_info', 'sections',
        'type_title', 'validation'
    ],
    // Fields to exclude from AlienVault geo section
    ALIENVAULT_GEO_EXCLUDE: [
        'accuracy_radius', 'area_code', 'charset', 'city_data', 'continent_code',
        'country_code2', 'country_code 2', 'country_code3', 'country_code 3',
        'dma_code', 'flag_title', 'flag_url', 'latitude', 'longitude'
    ],
    // Toast notification duration (ms)
    TOAST_DURATION: 5000,
    // API timeout (ms)
    API_TIMEOUT: 60000
};

// =============================================================================
// Security Utilities
// =============================================================================

/**
 * Escape HTML to prevent XSS attacks
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const str = String(text);
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return str.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Safely create text content without XSS risk
 * @param {string} text - Text content
 * @returns {Text} Text node
 */
function createTextNode(text) {
    return document.createTextNode(text);
}

// =============================================================================
// Toast Notification System
// =============================================================================

/**
 * Initialize toast container
 */
function initToastContainer() {
    if (!document.getElementById('toast-container')) {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - Type: 'success', 'error', 'warning', 'info'
 * @param {number} duration - Duration in ms (default: CONFIG.TOAST_DURATION)
 */
function showToast(message, type = 'info', duration = CONFIG.TOAST_DURATION) {
    initToastContainer();
    const container = document.getElementById('toast-container');

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    // Add close button
    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '&times;';
    closeBtn.style.cssText = 'background:none;border:none;color:inherit;font-size:1.2rem;cursor:pointer;margin-left:1rem;';
    closeBtn.onclick = () => toast.remove();
    toast.appendChild(closeBtn);

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// =============================================================================
// API Handler
// =============================================================================

/**
 * Get CSRF token from meta tag
 * @returns {string} CSRF token
 */
function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

/**
 * Make an API call with consistent error handling and loading states
 * @param {string} endpoint - API endpoint
 * @param {Object} data - Request data
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} API response
 */
async function apiCall(endpoint, data, options = {}) {
    const {
        method = 'POST',
        timeout = CONFIG.API_TIMEOUT,
        showLoading = true,
        loadingMessage = 'Processing...'
    } = options;

    if (showLoading) {
        showProgressBar(loadingMessage);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(endpoint, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify(data),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `HTTP error ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Request timed out. Please try again.');
        }
        throw error;
    } finally {
        if (showLoading) {
            hideProgressBar();
        }
    }
}

// =============================================================================
// Score and Value Utilities
// =============================================================================

/**
 * Get CSS class based on score
 * @param {number} score - Score value
 * @returns {string} CSS class name
 */
function getScoreClass(score) {
    if (score >= CONFIG.SCORE_THRESHOLDS.HIGH) return 'score-high';
    if (score >= CONFIG.SCORE_THRESHOLDS.MEDIUM) return 'score-medium';
    return 'score-low';
}

/**
 * Get badge class based on score
 * @param {number} score - Score value
 * @returns {string} Badge variant
 */
function getScoreBadgeClass(score) {
    if (score >= CONFIG.SCORE_THRESHOLDS.HIGH) return 'value-red';
    if (score >= CONFIG.SCORE_THRESHOLDS.MEDIUM) return 'value-yellow';
    return 'value-green';
}

/**
 * Render a value with appropriate styling (XSS-safe)
 * @param {*} value - Value to render
 * @param {string} key - Key name for context
 * @returns {string} Safe HTML string
 */
function renderValue(value, key = '') {
    // Handle arrays
    if (Array.isArray(value)) {
        if (value.length === 0) {
            return '<span class="data-value value-blue">N/A</span>';
        }
        return escapeHtml(value.join(', '));
    }

    // Handle objects
    if (typeof value === 'object' && value !== null) {
        if (Object.keys(value).length === 0) {
            return '<span class="data-value value-blue">N/A</span>';
        }
        return '<pre class="text-xs">' + escapeHtml(JSON.stringify(value, null, 2)) + '</pre>';
    }

    // Handle primitives
    const valStr = String(value).trim().toLowerCase();
    const escapedValue = escapeHtml(value);

    // Boolean-like values
    if (valStr === 'yes' || valStr === 'true') {
        return `<span class="data-value value-green">${escapedValue}</span>`;
    }
    if (valStr === 'no' || valStr === 'false') {
        return `<span class="data-value value-red">${escapedValue}</span>`;
    }

    // Empty/null values
    if (valStr === 'n/a' || valStr === '' || value === null || value === undefined) {
        return '<span class="data-value value-blue">N/A</span>';
    }

    // Numeric scores
    if (!isNaN(value) && value !== '' && value !== null) {
        const num = Number(value);
        return `<span class="data-value ${getScoreBadgeClass(num)}">${escapedValue}</span>`;
    }

    // Present keys (location, org, etc.)
    if (CONFIG.PRESENT_KEYS.includes(key.toLowerCase()) && valStr !== '') {
        return `<span class="data-value value-green">${escapedValue}</span>`;
    }

    return `<span class="data-value">${escapedValue}</span>`;
}

// =============================================================================
// Skeleton Loaders
// =============================================================================

/**
 * Create a skeleton card for loading states
 * @param {number} rows - Number of skeleton rows
 * @returns {string} Skeleton HTML
 */
function createSkeletonCard(rows = 5) {
    const skeletonRows = Array(rows).fill(0).map(() => `
        <div class="skeleton-row">
            <div class="skeleton skeleton-label"></div>
            <div class="skeleton skeleton-value"></div>
        </div>
    `).join('');

    return `
        <div class="skeleton-card">
            <div class="skeleton skeleton-title"></div>
            ${skeletonRows}
        </div>
    `;
}

/**
 * Create multiple skeleton cards
 * @param {number} count - Number of cards
 * @param {number} rowsPerCard - Rows per card
 * @returns {string} Multiple skeleton cards HTML
 */
function createSkeletonGrid(count = 3, rowsPerCard = 5) {
    return Array(count).fill(0).map(() => createSkeletonCard(rowsPerCard)).join('');
}

/**
 * Show skeleton loaders in a container
 * @param {HTMLElement} container - Container element
 * @param {number} count - Number of skeleton cards
 */
function showSkeletonLoaders(container, count = 3) {
    if (container) {
        container.innerHTML = createSkeletonGrid(count, 5);
        container.classList.remove('hidden');
    }
}

// =============================================================================
// Copy Button Utilities
// =============================================================================

/**
 * SVG icon for copy button
 */
const COPY_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;

/**
 * SVG icon for checkmark (copied state)
 */
const CHECK_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;

/**
 * Create a copy button HTML
 * @param {string} value - Value to copy
 * @returns {string} Copy button HTML
 */
function createCopyButton(value) {
    const safeValue = escapeHtml(String(value)).replace(/'/g, "\\'");
    return `<button class="copy-btn" onclick="handleCopyClick(this, '${safeValue}')" title="Copy to clipboard">${COPY_ICON}</button>`;
}

/**
 * Handle copy button click
 * @param {HTMLElement} button - The button element
 * @param {string} value - Value to copy
 */
function handleCopyClick(button, value) {
    navigator.clipboard.writeText(value).then(() => {
        button.innerHTML = CHECK_ICON;
        button.classList.add('copied');
        showToast('Copied to clipboard!', 'success', 2000);

        setTimeout(() => {
            button.innerHTML = COPY_ICON;
            button.classList.remove('copied');
        }, 2000);
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

// Make handleCopyClick globally available
window.handleCopyClick = handleCopyClick;

// =============================================================================
// UI Components
// =============================================================================

/**
 * Check if a value is copyable (meaningful single value)
 * @param {*} value - Value to check
 * @param {string} key - Key name
 * @returns {boolean} True if copyable
 */
function isCopyableValue(value, key) {
    if (typeof value !== 'string' && typeof value !== 'number') return false;
    const str = String(value).trim();
    if (!str || str === 'N/A' || str === 'null' || str === 'undefined') return false;
    // Copyable keys
    const copyableKeys = ['ip', 'domain', 'hostname', 'email', 'asn', 'org', 'organization',
        'isp', 'city', 'region', 'country', 'hash', 'md5', 'sha1', 'sha256', 'url'];
    return copyableKeys.some(k => key.toLowerCase().includes(k)) || str.length > 3;
}

/**
 * Create an info card component (XSS-safe) with copy buttons
 * @param {string} title - Card title
 * @param {Object} data - Data to display
 * @param {string} iconSvg - Optional icon SVG
 * @returns {string} Safe HTML string
 */
function createInfoCard(title, data, iconSvg = null) {
    const escapedTitle = escapeHtml(title);
    const rows = Object.entries(data)
        .filter(([key, value]) => {
            const valStr = String(value).trim().toLowerCase();
            return valStr && valStr !== 'n/a' && valStr !== 'null' && valStr !== 'undefined';
        })
        .map(([key, value], idx) => {
            const formattedKey = escapeHtml(
                key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
            );
            const renderedValue = renderValue(value, key);
            const copyBtn = isCopyableValue(value, key) ? createCopyButton(value) : '';

            return `
                <tr class="${idx % 2 === 1 ? 'bg-gray-800/80' : ''} hover:bg-gray-700/60 transition">
                    <td class="py-3 px-6 font-semibold text-gray-300">${formattedKey}</td>
                    <td class="py-3 px-6">
                        <span class="copyable-value">${renderedValue}${copyBtn}</span>
                    </td>
                </tr>
            `;
        }).join('');

    const disclaimer = title === 'VPN Checker' ? `
        <div class="mt-4 text-xs text-gray-400 italic bg-gray-900/80 rounded p-3">
            Disclaimer:<br>VPN data is cross-referenced and verified using multiple sources,
            including ABUSEIPDB, IPInfo, VPNIP.IO, and OpenCTI, to ensure the highest possible accuracy.
        </div>
    ` : '';

    return `
        <div class="info-card">
            <h3 class="text-2xl font-extrabold text-white mb-6 flex items-center gap-2">
                ${iconSvg || ''}
                ${escapedTitle}
            </h3>
            <table class="w-full text-left text-base divide-y divide-gray-700">
                <tbody>${rows}</tbody>
            </table>
            ${disclaimer}
        </div>
    `;
}

/**
 * Create abuse reports card (XSS-safe)
 * @param {Array} reports - Array of report objects
 * @returns {string} Safe HTML string
 */
function createAbuseReportsCard(reports) {
    if (!reports || !Array.isArray(reports) || reports.length === 0) return '';

    const topReports = reports.slice(0, 10);
    const reportItems = topReports.map(report => {
        const reportedAt = report.reportedAt
            ? escapeHtml(new Date(report.reportedAt).toLocaleString('en-US', { timeZone: 'UTC' }))
            : 'N/A';
        const categories = escapeHtml((report.categories || []).join(', ') || 'N/A');
        const comment = report.comment
            ? escapeHtml(report.comment)
            : '<span class="text-gray-500">No comment</span>';

        return `
            <div class="whois-item">
                <div class="whois-label">Reported At (UTC)</div>
                <div class="whois-value">${reportedAt}</div>
                <div class="whois-label">Category</div>
                <div class="whois-value">${categories}</div>
                <div class="whois-label">Comment</div>
                <div class="whois-value">${comment}</div>
            </div>
        `;
    }).join('');

    return `
        <div class="info-card">
            <h3 class="text-2xl font-extrabold text-white mb-6">AbuseIPDB Recent Reports</h3>
            <div class="whois-content">
                <div class="whois-grid" style="max-height: 350px; overflow-y: auto;">
                    ${reportItems}
                </div>
            </div>
        </div>
    `;
}

/**
 * Create WHOIS card (XSS-safe)
 * @param {Object} whoisData - WHOIS data object
 * @returns {string} Safe HTML string
 */
function createWhoisCard(whoisData) {
    if (!whoisData) return '';

    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return escapeHtml(date.toLocaleDateString() + ' ' + date.toLocaleTimeString());
    };

    const formatContact = (contact) => {
        if (!contact) return '';
        const fields = [
            ['Name', contact.name],
            ['Organization', contact.organization],
            ['Email', contact.email],
            ['Phone', contact.phone],
            ['Address', contact.street_address],
            ['City', contact.city],
            ['Region', contact.region],
            ['Country', contact.country]
        ];

        const items = fields.map(([label, value]) => `
            <div class="whois-item">
                <div class="whois-label">${escapeHtml(label)}</div>
                <div class="whois-value">${escapeHtml(value || 'N/A')}</div>
            </div>
        `).join('');

        return `<div class="whois-section"><div class="whois-grid">${items}</div></div>`;
    };

    const nameservers = (whoisData.nameservers || []).map(ns => `
        <div class="whois-item">
            <div class="whois-value">${escapeHtml(ns)}</div>
        </div>
    `).join('');

    return `
        <div class="info-card">
            <h3 class="text-2xl font-extrabold text-white mb-6">WHOIS Information</h3>
            <div class="whois-content">
                <!-- Domain Information -->
                <div class="whois-section">
                    <div class="whois-section-title text-blue-400">Domain Information</div>
                    <div class="whois-grid">
                        <div class="whois-item">
                            <div class="whois-label">Domain</div>
                            <div class="whois-value">${escapeHtml(whoisData.domain || 'N/A')}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Status</div>
                            <div class="whois-value">${escapeHtml(whoisData.status || 'N/A')}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Registrar</div>
                            <div class="whois-value">${escapeHtml(whoisData.registrar?.name || 'N/A')}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Domain Age</div>
                            <div class="whois-value">${whoisData.domain_age ? escapeHtml(whoisData.domain_age + ' days') : 'N/A'}</div>
                        </div>
                    </div>
                </div>
                <!-- Dates -->
                <div class="whois-section">
                    <div class="whois-section-title text-blue-400">Important Dates</div>
                    <div class="whois-dates">
                        <div class="whois-date-item">
                            <div class="whois-date-label">Created</div>
                            <div class="whois-date-value">${formatDate(whoisData.create_date)}</div>
                        </div>
                        <div class="whois-date-item">
                            <div class="whois-date-label">Updated</div>
                            <div class="whois-date-value">${formatDate(whoisData.update_date)}</div>
                        </div>
                        <div class="whois-date-item">
                            <div class="whois-date-label">Expires</div>
                            <div class="whois-date-value">${formatDate(whoisData.expire_date)}</div>
                        </div>
                    </div>
                </div>
                <!-- Nameservers -->
                <div class="whois-section">
                    <div class="whois-section-title text-blue-400">Nameservers</div>
                    <div class="whois-grid">${nameservers}</div>
                </div>
                ${whoisData.registrant ? `
                    <div class="whois-section">
                        <div class="whois-section-title text-blue-400">Registrant Information</div>
                        ${formatContact(whoisData.registrant)}
                    </div>
                ` : ''}
                ${whoisData.admin ? `
                    <div class="whois-section">
                        <div class="whois-section-title text-blue-400">Admin Information</div>
                        ${formatContact(whoisData.admin)}
                    </div>
                ` : ''}
                ${whoisData.tech ? `
                    <div class="whois-section">
                        <div class="whois-section-title text-blue-400">Technical Information</div>
                        ${formatContact(whoisData.tech)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Create Shodan card with recursive value rendering (XSS-safe)
 * @param {Object} shodanData - Shodan data object
 * @returns {string} Safe HTML string
 */
function createShodanCard(shodanData) {
    if (!shodanData) return '';

    function renderShodanValue(value, depth = 0, seen = new WeakSet()) {
        if (depth > 5) return '<span class="text-gray-400">[Max depth reached]</span>';
        if (value === null || value === undefined) return '<span class="text-gray-400">N/A</span>';

        if (typeof value === 'string') {
            try {
                const parsed = JSON.parse(value);
                if (typeof parsed === 'object') return renderShodanValue(parsed, depth + 1, seen);
            } catch (e) { /* Not JSON, continue */ }
            return escapeHtml(value);
        }

        if (typeof value === 'object') {
            if (seen.has(value)) return '<span class="text-gray-400">[Circular]</span>';
            seen.add(value);

            if (Array.isArray(value)) {
                if (value.length === 0) return '<span class="text-gray-400">None</span>';
                if (value.every(v => typeof v === 'object' && v !== null)) {
                    return value.map((obj, idx) => `
                        <div class="mb-2">
                            <div class="text-xs text-blue-400 mb-1">Item ${idx + 1}</div>
                            ${renderShodanValue(obj, depth + 1, seen)}
                        </div>
                    `).join('');
                }
                return '<ul class="pl-4 list-disc">' +
                    value.map(v => `<li>${renderShodanValue(v, depth + 1, seen)}</li>`).join('') +
                    '</ul>';
            }

            const entries = Object.entries(value).filter(([k, v]) => v !== undefined);
            if (entries.length === 0) return '<span class="text-gray-400">None</span>';

            return '<table class="w-full text-sm text-left text-gray-300">' +
                entries.map(([k, v]) => `
                    <tr>
                        <td class="font-semibold pr-2 align-top">${escapeHtml(k)}</td>
                        <td>${renderShodanValue(v, depth + 1, seen)}</td>
                    </tr>
                `).join('') +
                '</table>';
        }

        return escapeHtml(String(value));
    }

    return `
        <div class="info-card">
            <h3 class="text-2xl font-extrabold text-white mb-6">Shodan Information</h3>
            <div class="shodan-content">${renderShodanValue(shodanData)}</div>
        </div>
    `;
}

// =============================================================================
// Specialized Cards
// =============================================================================

/**
 * Create ProxyCheck card with security indicators (XSS-safe)
 * @param {Object} data - ProxyCheck data
 * @returns {string} Safe HTML string
 */
function createProxyCheckCard(data) {
    if (!data) return '';

    // Extract key security indicators
    const isProxy = data.proxy === 'yes';
    const isVPN = data.vpn === 'yes';
    const isTor = data.type?.toLowerCase().includes('tor');
    const risk = parseInt(data.risk) || 0;

    // Determine overall risk level
    let riskLevel = 'low';
    let riskColor = 'green';
    if (risk >= 75 || isProxy || isVPN || isTor) {
        riskLevel = 'high';
        riskColor = 'red';
    } else if (risk >= 25) {
        riskLevel = 'medium';
        riskColor = 'yellow';
    }

    // Security badges
    const badges = [];
    if (isVPN) badges.push('<span class="status-badge status-danger">VPN</span>');
    if (isProxy) badges.push('<span class="status-badge status-danger">Proxy</span>');
    if (isTor) badges.push('<span class="status-badge status-danger">Tor</span>');
    if (badges.length === 0) badges.push('<span class="status-badge status-success">Clean</span>');

    // Filter and format data
    const filteredData = filterProxyCheckFields(data);
    const rows = Object.entries(filteredData)
        .filter(([key, value]) => {
            const valStr = String(value).trim().toLowerCase();
            return valStr && valStr !== 'n/a' && valStr !== 'null';
        })
        .map(([key, value], idx) => {
            const formattedKey = escapeHtml(
                key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
            );
            const renderedValue = renderValue(value, key);
            const copyBtn = isCopyableValue(value, key) ? createCopyButton(value) : '';

            return `
                <tr class="${idx % 2 === 1 ? 'bg-gray-800/80' : ''} hover:bg-gray-700/60 transition">
                    <td class="py-3 px-6 font-semibold text-gray-300">${formattedKey}</td>
                    <td class="py-3 px-6">
                        <span class="copyable-value">${renderedValue}${copyBtn}</span>
                    </td>
                </tr>
            `;
        }).join('');

    return `
        <div class="info-card">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-2xl font-extrabold text-white flex items-center gap-2">
                    ProxyCheck.io
                </h3>
                <div class="flex items-center gap-2">
                    ${badges.join('')}
                </div>
            </div>
            <div class="bg-gray-800/50 rounded-lg p-4 mb-4">
                <div class="flex items-center justify-between">
                    <span class="text-gray-400">Risk Score</span>
                    <div class="flex items-center gap-3">
                        <div class="w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div class="h-full bg-${riskColor}-500" style="width: ${risk}%"></div>
                        </div>
                        <span class="text-${riskColor}-400 font-bold">${risk}%</span>
                    </div>
                </div>
            </div>
            <table class="w-full text-left text-base divide-y divide-gray-700">
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

/**
 * Create Intezer Analysis card with verdict visualization (XSS-safe)
 * @param {Object} data - Intezer analysis data
 * @returns {string} Safe HTML string
 */
function createIntezerCard(data) {
    if (!data) return '';

    // Determine verdict styling
    const verdict = (data.verdict || 'unknown').toLowerCase();
    let verdictColor = 'gray';
    let verdictIcon = '❓';

    if (verdict === 'malicious') {
        verdictColor = 'red';
        verdictIcon = '🔴';
    } else if (verdict === 'suspicious') {
        verdictColor = 'yellow';
        verdictIcon = '🟡';
    } else if (verdict === 'trusted' || verdict === 'known' || verdict === 'benign') {
        verdictColor = 'green';
        verdictIcon = '🟢';
    } else if (verdict === 'no_threats') {
        verdictColor = 'green';
        verdictIcon = '✅';
    }

    // Build summary section
    const summaryItems = [];
    if (data.verdict) {
        summaryItems.push(`
            <div class="flex items-center gap-2">
                <span class="text-gray-400">Verdict:</span>
                <span class="text-${verdictColor}-400 font-bold uppercase">${escapeHtml(data.verdict)}</span>
            </div>
        `);
    }
    if (data.sub_verdict) {
        summaryItems.push(`
            <div class="flex items-center gap-2">
                <span class="text-gray-400">Sub-verdict:</span>
                <span class="text-${verdictColor}-400">${escapeHtml(data.sub_verdict)}</span>
            </div>
        `);
    }
    if (data.family_name) {
        summaryItems.push(`
            <div class="flex items-center gap-2">
                <span class="text-gray-400">Malware Family:</span>
                <span class="text-red-400 font-bold">${escapeHtml(data.family_name)}</span>
            </div>
        `);
    }
    if (data.threat_type) {
        summaryItems.push(`
            <div class="flex items-center gap-2">
                <span class="text-gray-400">Threat Type:</span>
                <span class="text-orange-400">${escapeHtml(data.threat_type)}</span>
            </div>
        `);
    }

    // Build details table
    const detailFields = ['sha256', 'analysis_id', 'analysis_time', 'classification'];
    const rows = detailFields
        .filter(key => data[key])
        .map((key, idx) => {
            const formattedKey = escapeHtml(
                key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
            );
            const value = data[key];
            const copyBtn = isCopyableValue(value, key) ? createCopyButton(value) : '';

            return `
                <tr class="${idx % 2 === 1 ? 'bg-gray-800/80' : ''} hover:bg-gray-700/60 transition">
                    <td class="py-3 px-6 font-semibold text-gray-300">${formattedKey}</td>
                    <td class="py-3 px-6">
                        <span class="copyable-value">${escapeHtml(value)}${copyBtn}</span>
                    </td>
                </tr>
            `;
        }).join('');

    // Analysis URL link
    const analysisLink = data.analysis_url
        ? `<a href="${escapeHtml(data.analysis_url)}" target="_blank" rel="noopener" class="text-blue-400 hover:underline text-sm">View Full Analysis →</a>`
        : '';

    return `
        <div class="info-card">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-2xl font-extrabold text-white flex items-center gap-2">
                    Intezer Analysis
                </h3>
                <span class="text-2xl">${verdictIcon}</span>
            </div>
            <div class="bg-gray-800/50 rounded-lg p-4 mb-4 border-l-4 border-${verdictColor}-500">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    ${summaryItems.join('')}
                </div>
            </div>
            ${rows ? `
                <table class="w-full text-left text-base divide-y divide-gray-700 mb-4">
                    <tbody>${rows}</tbody>
                </table>
            ` : ''}
            ${analysisLink}
        </div>
    `;
}

// =============================================================================
// Data Filters
// =============================================================================

/**
 * Filter ProxyCheck fields
 * @param {Object} data - ProxyCheck data
 * @returns {Object} Filtered data
 */
function filterProxyCheckFields(data) {
    return Object.fromEntries(
        Object.entries(data).filter(([key]) =>
            !CONFIG.PROXYCHECK_EXCLUDE.includes(key.toLowerCase())
        )
    );
}

/**
 * Filter AlienVault fields based on section
 * @param {Object} data - AlienVault data
 * @param {string} section - Section name
 * @returns {Object} Filtered data
 */
function filterAlienVaultFields(data, section) {
    const excludeList = section === 'general'
        ? CONFIG.ALIENVAULT_GENERAL_EXCLUDE
        : section === 'geo'
            ? CONFIG.ALIENVAULT_GEO_EXCLUDE
            : [];

    return Object.fromEntries(
        Object.entries(data).filter(([key]) =>
            !excludeList.includes(key.toLowerCase())
        )
    );
}

// =============================================================================
// Progress Bar
// =============================================================================

/**
 * Show progress bar with label
 * @param {string} label - Progress label
 */
function showProgressBar(label = 'Processing...') {
    const bar = document.getElementById('progress-bar');
    const labelEl = document.getElementById('progress-label');

    if (bar) bar.classList.remove('hidden');
    if (labelEl) labelEl.textContent = label;

    const inner = bar?.querySelector('.progress-bar-inner');
    if (inner) {
        inner.style.width = '100%';
        inner.classList.add('progress-bar-animated');
    }
}

/**
 * Hide progress bar
 */
function hideProgressBar() {
    const bar = document.getElementById('progress-bar');
    if (bar) bar.classList.add('hidden');

    const inner = bar?.querySelector('.progress-bar-inner');
    if (inner) {
        inner.style.width = '0%';
        inner.classList.remove('progress-bar-animated');
    }
}

// =============================================================================
// Report Toggle
// =============================================================================

/**
 * Toggle reports dropdown
 * @param {HTMLElement} element - Trigger element
 */
function toggleReports(element) {
    const dropdown = element.nextElementSibling;
    const icon = element.querySelector('.dropdown-icon');
    dropdown?.classList.toggle('active');
    icon?.classList.toggle('active');
}

// =============================================================================
// Export Functions
// =============================================================================

/**
 * Handle PDF export
 */
function handleExportPDF() {
    if (window.lastCheckedData) {
        exportToPDF(window.lastCheckedData.ip, window.lastCheckedData.data);
    } else {
        showToast('Please check an IP address first before exporting to PDF.', 'warning');
    }
}

/**
 * Export data to PDF
 * @param {string} ip - IP address
 * @param {Object} data - Data to export
 */
function exportToPDF(ip, data) {
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        doc.setFontSize(20);
        doc.text('IP Information Report', 20, 20);

        doc.setFontSize(14);
        doc.text(`IP Address: ${ip}`, 20, 30);

        doc.setFontSize(10);
        doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 40);

        let y = 50;

        function addSection(title, sectionData) {
            doc.setFontSize(12);
            doc.setFont(undefined, 'bold');
            doc.text(title, 20, y);
            y += 10;

            doc.setFont(undefined, 'normal');
            const tableData = Object.entries(sectionData).map(([key, value]) => [
                key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                String(value || 'N/A')
            ]);

            doc.autoTable({
                startY: y,
                head: [['Property', 'Value']],
                body: tableData,
                theme: 'grid',
                headStyles: { fillColor: [41, 128, 185] },
                styles: { fontSize: 10 }
            });

            y = doc.lastAutoTable.finalY + 10;
        }

        // Add sections based on available data
        if (data.abuse) {
            addSection('Abuse Information', {
                'Abuse Score': `${data.abuse.abuse_confidence_score}%`,
                'Total Reports': data.abuse.total_reports,
                'Distinct Users': data.abuse.distinct_users,
                'Last Reported': data.abuse.last_reported || 'N/A',
                'Usage Type': data.abuse.usage_type || 'N/A',
                'ISP': data.abuse.isp || 'N/A',
                'Domain': data.abuse.domain || 'N/A',
                'Whitelisted': data.abuse.is_whitelisted ? 'Yes' : 'No'
            });
        }

        if (data.ipinfo) {
            addSection('IPinfo Data', {
                'Hostname': data.ipinfo.hostname || 'N/A',
                'City': data.ipinfo.city || 'N/A',
                'Region': data.ipinfo.region || 'N/A',
                'Country': data.ipinfo.country || 'N/A',
                'Location': data.ipinfo.loc || 'N/A',
                'Organization': data.ipinfo.org || 'N/A'
            });
        }

        if (data.security) {
            addSection('Security Information', {
                'VPN': data.security.vpn ? 'Yes' : 'No',
                'Proxy': data.security.proxy ? 'Yes' : 'No',
                'Tor': data.security.tor ? 'Yes' : 'No',
                'Relay': data.security.relay ? 'Yes' : 'No'
            });
        }

        if (data.location) {
            addSection('Location Data', {
                'City': data.location.city || 'N/A',
                'Region': data.location.region || 'N/A',
                'Country': data.location.country || 'N/A',
                'Continent': data.location.continent || 'N/A'
            });
        }

        // Add footer
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.text(`Page ${i} of ${pageCount}`, 20, doc.internal.pageSize.height - 10);
            doc.text('Generated by NexusTrace', doc.internal.pageSize.width - 20, doc.internal.pageSize.height - 10, { align: 'right' });
        }

        doc.save(`IP_Report_${ip.replace(/\./g, '_')}.pdf`);
        showToast('PDF exported successfully!', 'success');
    } catch (error) {
        console.error('Error generating PDF:', error);
        showToast('Error generating PDF. Please try again.', 'error');
    }
}

/**
 * Handle screenshot export
 */
function handleExportScreenshot() {
    const grid = document.querySelector('.content-grid');
    if (!grid) {
        showToast('No information to export. Please analyze an IP first.', 'warning');
        return;
    }

    html2canvas(grid, {
        backgroundColor: '#181f2a',
        scale: 2,
        useCORS: true,
        windowWidth: grid.scrollWidth,
        windowHeight: grid.scrollHeight
    }).then(canvas => {
        const link = document.createElement('a');
        link.download = 'nexustrace_report.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
        showToast('Screenshot exported successfully!', 'success');
    }).catch(error => {
        console.error('Error generating screenshot:', error);
        showToast('Error generating screenshot. Please try again.', 'error');
    });
}

// =============================================================================
// Navigation
// =============================================================================

/**
 * Show a specific section
 * @param {string} sectionId - Section ID to show
 */
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('visible');
        section.style.display = 'none';
    });

    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = 'block';
        setTimeout(() => section.classList.add('visible'), 10);
    }

    document.querySelectorAll('.toolbar-link').forEach(link => {
        link.classList.remove('active');
    });

    const navLinks = {
        'ip-section': 0,
        'domain-section': 1,
        'url-section': 2
    };

    const toolbarLinks = document.querySelectorAll('.toolbar-link');
    if (navLinks[sectionId] !== undefined && toolbarLinks[navLinks[sectionId]]) {
        toolbarLinks[navLinks[sectionId]].classList.add('active');
    }

    localStorage.setItem('lastSection', sectionId);
}

/**
 * Get query parameter from URL
 * @param {string} name - Parameter name
 * @returns {string|null} Parameter value
 */
function getQueryParam(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

/**
 * Highlight toolbar link based on path
 * @param {string} path - Current path
 */
function highlightToolbarLinkByPath(path) {
    document.querySelectorAll('.toolbar-link').forEach(link => {
        link.classList.remove('active');
    });

    const selector = `.toolbar-link[href="${path}"]`;
    document.querySelector(selector)?.classList.add('active');
}

// =============================================================================
// Card Height Equalization
// =============================================================================

/**
 * Equalize heights of cards in result rows
 */
function equalizeRowHeights() {
    document.querySelectorAll('.results-row').forEach(row => {
        const cards = row.querySelectorAll('.info-card, .whois-card, .shodan-card');

        // Reset heights
        cards.forEach(card => card.style.height = 'auto');

        // Find max height
        let maxHeight = 0;
        cards.forEach(card => {
            maxHeight = Math.max(maxHeight, card.offsetHeight);
        });

        // Apply max height
        cards.forEach(card => card.style.height = maxHeight + 'px');
    });
}

/**
 * Run equalize after results load
 */
function runEqualizeAfterResults() {
    setTimeout(equalizeRowHeights, 100);
}

// =============================================================================
// Form Handlers
// =============================================================================

/**
 * Handle IP form submission
 * @param {Event} e - Submit event
 */
async function handleIPFormSubmit(e) {
    e.preventDefault();

    const ip = document.getElementById('ip-input')?.value.trim();
    if (!ip) {
        showToast('Please enter an IP address', 'warning');
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const loading = document.getElementById('ip-loading');
    const results = document.getElementById('ip-results');

    // Add loading state to button
    if (submitBtn) {
        submitBtn.classList.add('btn-loading');
        submitBtn.disabled = true;
    }

    // Show skeleton loaders in each section
    const sections = ['vpn-results', 'geo-network-results', 'abuseipdb-results', 'alienvault-results', 'shodan-results'];
    sections.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            showSkeletonLoaders(el, 2);
        }
    });

    if (loading) loading.classList.remove('hidden');
    if (results) results.classList.remove('hidden');

    try {
        const data = await apiCall('/api/ip/check_ip', { ip }, {
            loadingMessage: 'Analyzing IP address...'
        });

        // Store for export
        window.lastCheckedData = { ip, data };

        // VPN/Security Section
        const vpnResults = document.getElementById('vpn-results');
        if (vpnResults) {
            vpnResults.innerHTML = '';
            if (data.security) {
                vpnResults.innerHTML += createInfoCard('VPNAPI.io VPN Checker', data.security);
            }
            if (data.ipinfo?.privacy) {
                vpnResults.innerHTML += createInfoCard('IPInfo.io Privacy Information', data.ipinfo.privacy);
            }
            if (data.proxycheck) {
                vpnResults.innerHTML += createProxyCheckCard(data.proxycheck);
            }
        }

        // Geo/Network Section
        const geoNetworkResults = document.getElementById('geo-network-results');
        if (geoNetworkResults) {
            geoNetworkResults.innerHTML = '';
            if (data.location) {
                geoNetworkResults.innerHTML += createInfoCard('VPNAPI Location Data', data.location);
            }
            if (data.network) {
                geoNetworkResults.innerHTML += createInfoCard('VPNAPI Network Data', data.network);
            }
            if (data.ipinfo) {
                geoNetworkResults.innerHTML += createInfoCard('IPinfo Data', data.ipinfo);
            }
            if (data.alienvault?.geo) {
                geoNetworkResults.innerHTML += createInfoCard('AlienVault: Geo', data.alienvault.geo);
            }
        }

        // AbuseIPDB Section
        const abuseipdbResults = document.getElementById('abuseipdb-results');
        if (abuseipdbResults) {
            abuseipdbResults.innerHTML = '';
            if (data.abuse) {
                const { reports, ...abuseInfoNoReports } = data.abuse;
                abuseipdbResults.innerHTML += createInfoCard('Abuse Info', abuseInfoNoReports);
                if (reports?.length) {
                    abuseipdbResults.innerHTML += createAbuseReportsCard(reports);
                }
            }
        }

        // AlienVault Section
        const alienvaultResults = document.getElementById('alienvault-results');
        if (alienvaultResults) {
            alienvaultResults.innerHTML = '';
            if (data.alienvault && typeof data.alienvault === 'object') {
                const excludeSections = ['malware', 'http_scans', 'passive_dns', 'url_list'];
                const avSections = Object.entries(data.alienvault)
                    .filter(([k, v]) => v && typeof v === 'object' && !excludeSections.includes(k));

                avSections.forEach(([section, sectionData]) => {
                    const title = `AlienVault: ${section.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
                    alienvaultResults.innerHTML += createInfoCard(title, filterAlienVaultFields(sectionData, section));
                });
            }
        }

        // Shodan Section
        const shodanResults = document.getElementById('shodan-results');
        if (shodanResults) {
            shodanResults.innerHTML = '';
            if (data.shodan) {
                shodanResults.innerHTML += createShodanCard(data.shodan);
            }
        }

        if (results) results.classList.remove('hidden');
        runEqualizeAfterResults();

    } catch (error) {
        showToast(error.message || 'Error fetching IP data', 'error');
        sections.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = `<div class="text-red-400 p-4">Error: ${escapeHtml(error.message)}</div>`;
        });
    } finally {
        if (loading) loading.classList.add('hidden');
        if (submitBtn) {
            submitBtn.classList.remove('btn-loading');
            submitBtn.disabled = false;
        }
    }
}

/**
 * Handle Domain form submission
 * @param {Event} e - Submit event
 */
async function handleDomainFormSubmit(e) {
    e.preventDefault();

    const domain = document.getElementById('domain-input')?.value.trim();
    if (!domain) {
        showToast('Please enter a domain', 'warning');
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const loading = document.getElementById('domain-loading');
    const results = document.getElementById('domain-results');

    // Add loading state to button
    if (submitBtn) {
        submitBtn.classList.add('btn-loading');
        submitBtn.disabled = true;
    }

    // Show skeleton loaders
    if (results) {
        showSkeletonLoaders(results, 3);
        results.classList.remove('hidden');
    }
    if (loading) loading.classList.remove('hidden');

    try {
        const data = await apiCall('/api/domain/check_domain', { domain }, {
            loadingMessage: 'Analyzing domain...'
        });

        if (results) {
            results.innerHTML = '';
            if (data.whois) results.innerHTML += createWhoisCard(data.whois);
            if (data.dns_records) results.innerHTML += createInfoCard('DNS Records', data.dns_records);
            if (data.ssl_info) results.innerHTML += createInfoCard('SSL Certificate', data.ssl_info);
            results.classList.remove('hidden');
        }

    } catch (error) {
        showToast(error.message || 'Error fetching domain data', 'error');
        if (results) results.innerHTML = `<div class="text-red-400 p-4">Error: ${escapeHtml(error.message)}</div>`;
    } finally {
        if (loading) loading.classList.add('hidden');
        if (submitBtn) {
            submitBtn.classList.remove('btn-loading');
            submitBtn.disabled = false;
        }
    }
}

/**
 * Handle URL form submission
 * @param {Event} e - Submit event
 */
async function handleURLFormSubmit(e) {
    e.preventDefault();

    const url = document.getElementById('url-input')?.value.trim();
    if (!url) {
        showToast('Please enter a URL', 'warning');
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const loading = document.getElementById('url-loading');
    const results = document.getElementById('url-results');

    // Add loading state to button
    if (submitBtn) {
        submitBtn.classList.add('btn-loading');
        submitBtn.disabled = true;
    }

    // Show skeleton loaders
    if (results) {
        showSkeletonLoaders(results, 4);
        results.classList.remove('hidden');
    }
    if (loading) loading.classList.remove('hidden');

    try {
        const data = await apiCall('/api/url/analyze_url', { url }, {
            loadingMessage: 'Analyzing URL...'
        });

        if (results && data.url_analysis) {
            results.innerHTML = '';
            const analysis = data.url_analysis;

            if (analysis.parsed_url) results.innerHTML += createInfoCard('URL Structure', analysis.parsed_url);
            if (analysis.response) results.innerHTML += createInfoCard('Response Information', analysis.response);
            if (analysis.security_headers) results.innerHTML += createInfoCard('Security Headers', analysis.security_headers);
            if (analysis.technologies) results.innerHTML += createInfoCard('Technology Stack', analysis.technologies);
            if (analysis.intezer_analysis) results.innerHTML += createIntezerCard(analysis.intezer_analysis);

            results.classList.remove('hidden');
        }

    } catch (error) {
        showToast(error.message || 'Error fetching URL data', 'error');
        if (results) results.innerHTML = `<div class="text-red-400 p-4">Error: ${escapeHtml(error.message)}</div>`;
    } finally {
        if (loading) loading.classList.add('hidden');
        if (submitBtn) {
            submitBtn.classList.remove('btn-loading');
            submitBtn.disabled = false;
        }
    }
}

// =============================================================================
// Copy to Clipboard
// =============================================================================

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {string} label - Label for toast message
 */
function copyToClipboard(text, label = 'Value') {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`${label} copied to clipboard!`, 'success', 2000);
    }).catch(() => {
        showToast('Failed to copy to clipboard', 'error');
    });
}

// Make copy function globally available
window.copyToClipboard = copyToClipboard;

// =============================================================================
// Initialization
// =============================================================================

window.addEventListener('DOMContentLoaded', () => {
    // Initialize toast container
    initToastContainer();

    // Handle routing
    const path = window.location.pathname;
    if (path === '/domain') {
        showSection('domain-section');
        highlightToolbarLinkByPath(path);
    } else if (path === '/ip') {
        showSection('ip-section');
        highlightToolbarLinkByPath(path);
    } else if (path === '/url') {
        showSection('url-section');
        highlightToolbarLinkByPath(path);
    } else if (path === '/') {
        return;
    } else {
        const lastSection = localStorage.getItem('lastSection') || 'ip-section';
        showSection(lastSection);
        const pathMap = {
            'domain-section': '/domain',
            'ip-section': '/ip',
            'url-section': '/url'
        };
        highlightToolbarLinkByPath(pathMap[lastSection] || '/ip');
    }

    // Attach form handlers
    const ipForm = document.getElementById('ip-form');
    if (ipForm) ipForm.addEventListener('submit', handleIPFormSubmit);

    const domainForm = document.getElementById('domain-form');
    if (domainForm) domainForm.addEventListener('submit', handleDomainFormSubmit);

    const urlForm = document.getElementById('url-form');
    if (urlForm) urlForm.addEventListener('submit', handleURLFormSubmit);
});

// Export functions to window for global access
window.runEqualizeAfterResults = runEqualizeAfterResults;
window.showToast = showToast;
window.toggleReports = toggleReports;
window.handleExportPDF = handleExportPDF;
window.handleExportScreenshot = handleExportScreenshot;
window.showSection = showSection;
