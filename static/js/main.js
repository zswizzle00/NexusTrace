// Utility functions
function getScoreClass(score) {
    if (score >= 75) return 'score-high';
    if (score >= 25) return 'score-medium';
    return 'score-low';
}

function toggleReports(element) {
    const dropdown = element.nextElementSibling;
    const icon = element.querySelector('.dropdown-icon');
    dropdown.classList.toggle('active');
    icon.classList.toggle('active');
}

// Helper to render nested values with color coding
function renderValue(value, key = '') {
    if (Array.isArray(value)) {
        // Join arrays as comma-separated string for table display
        return value.length === 0 ? '<span class="data-value value-blue">N/A</span>' : value.join(', ');
    } else if (typeof value === 'object' && value !== null) {
        // Render objects as JSON string (or flatten if you want)
        return Object.keys(value).length === 0 ? '<span class="data-value value-blue">N/A</span>' : JSON.stringify(value);
    } else {
        // Color coding for yes/no/N/A and scores
        let valStr = String(value).trim().toLowerCase();
        const presentKeys = [
            'country', 'country code', 'country_name', 'countrycode', 'region', 'regioncode', 'city', 'organization', 'organisation', 'org', 'provider', 'asn', 'hostname', 'name', 'symbol', 'type', 'range', 'address', 'postcode', 'timezone', 'continent', 'continentcode', 'currency', 'code', 'iso', 'isocode', 'latitude', 'longitude'
        ];
        if (valStr === 'yes' || valStr === 'true') {
            return `<span class="data-value value-green">${value}</span>`;
        } else if (valStr === 'no' || valStr === 'false') {
            return `<span class="data-value value-red">${value}</span>`;
        } else if (valStr === 'n/a' || valStr === '' || value === null || value === undefined) {
            return `<span class="data-value value-blue">N/A</span>`;
        } else if (!isNaN(value) && value !== '' && value !== null && value !== undefined) {
            // Score color coding
            const num = Number(value);
            if (num >= 75) return `<span class="data-value value-red">${value}</span>`;
            if (num >= 25) return `<span class="data-value value-yellow">${value}</span>`;
            if (num >= 0) return `<span class="data-value value-green">${value}</span>`;
        } else if (presentKeys.includes(key.toLowerCase()) && valStr !== '') {
            return `<span class="data-value value-green">${value}</span>`;
        }
        return `<span class="data-value">${value}</span>`;
    }
}

function createInfoCard(title, data, iconSvg = null) {
    return `
        <div class="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8 w-full h-full flex flex-col">
            <h3 class="text-3xl font-extrabold text-white mb-6 flex items-center gap-2">
                ${iconSvg ? iconSvg : ''}
                ${title}
            </h3>
            <table class="w-full text-left text-base divide-y divide-gray-700">
                <tbody>
                    ${Object.entries(data)
                        .filter(([key, value]) => {
                            const valStr = String(value).trim().toLowerCase();
                            return valStr && valStr !== 'n/a' && valStr !== 'null' && valStr !== 'undefined';
                        })
                        .map(([key, value], idx) => `
                            <tr class="${idx % 2 === 1 ? 'bg-gray-800/80' : ''} hover:bg-gray-700/60 transition">
                                <td class="py-3 px-6 font-semibold text-gray-300">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</td>
                                <td class="py-3 px-6">${renderModernValue(value, key)}</td>
                            </tr>
                        `).join('')}
                </tbody>
            </table>
            ${title === 'VPN Checker' ? `<div class='mt-4 text-xs text-gray-400 italic bg-gray-900/80 rounded p-3'>Disclaimer:<br>VPN data is cross-referenced and verified using multiple sources, including ABUSEIPDB, IPInfo, VPNIP.IO, and OpenCTI, to ensure the highest possible accuracy. In cases where discrepancies exist between sources, all available data will be displayed in the user interface. When data from the sources aligns, the consolidated information will be presented.</div>` : ''}
        </div>
    `;
}

// Modern value rendering with colored badges for booleans and N/A
function renderModernValue(value, key = '') {
    if (Array.isArray(value)) {
        return value.length === 0 ? '<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-blue-900 text-blue-300">N/A</span>' : value.join(', ');
    } else if (typeof value === 'object' && value !== null) {
        return Object.keys(value).length === 0 ? '<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-blue-900 text-blue-300">N/A</span>' : JSON.stringify(value);
    } else {
        let valStr = String(value).trim().toLowerCase();
        if (valStr === 'yes' || valStr === 'true') {
            return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-green-900 text-green-400">${value}</span>`;
        } else if (valStr === 'no' || valStr === 'false') {
            return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-red-900 text-red-400">${value}</span>`;
        } else if (valStr === 'n/a' || valStr === '' || value === null || value === undefined) {
            return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-blue-900 text-blue-300">N/A</span>`;
        } else if (!isNaN(value) && value !== '' && value !== null && value !== undefined) {
            // Score color coding
            const num = Number(value);
            if (num >= 75) return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-red-900 text-red-400">${value}</span>`;
            if (num >= 25) return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-yellow-900 text-yellow-400">${value}</span>`;
            if (num >= 0) return `<span class="inline-block px-3 py-1 rounded-full text-sm font-bold bg-green-900 text-green-400">${value}</span>`;
        }
        return `<span class="text-gray-200">${value}</span>`;
    }
}

function createAbuseReportsCard(reports) {
    if (!reports || !Array.isArray(reports) || reports.length === 0) return '';
    const topReports = reports.slice(0, 10);
    return `
        <div class="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8 w-full h-full flex flex-col">
            <h3 class="text-2xl font-extrabold text-white mb-6">AbuseIPDB Recent Reports</h3>
            <div class="whois-content">
                <div class="whois-grid" style="max-height: 350px; overflow-y: auto;">
                    ${topReports.map(report => `
                        <div class="whois-item">
                            <div class="whois-label">Reported At (UTC)</div>
                            <div class="whois-value">${report.reportedAt ? new Date(report.reportedAt).toLocaleString('en-US', { timeZone: 'UTC' }) : 'N/A'}</div>
                            <div class="whois-label">Category</div>
                            <div class="whois-value">${(report.categories || []).join(', ') || 'N/A'}</div>
                            <div class="whois-label">Comment</div>
                            <div class="whois-value">${report.comment ? report.comment : '<span class=\"text-gray-500\">No comment</span>'}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function createWhoisCard(whoisData) {
    if (!whoisData) return '';
    
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    };
    
    const formatContact = (contact) => {
        if (!contact) return '';
        return `
            <div class="whois-section">
                <div class="whois-grid">
                    <div class="whois-item">
                        <div class="whois-label">Name</div>
                        <div class="whois-value">${contact.name || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Organization</div>
                        <div class="whois-value">${contact.organization || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Email</div>
                        <div class="whois-value">${contact.email || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Phone</div>
                        <div class="whois-value">${contact.phone || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Address</div>
                        <div class="whois-value">${contact.street_address || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">City</div>
                        <div class="whois-value">${contact.city || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Region</div>
                        <div class="whois-value">${contact.region || 'N/A'}</div>
                    </div>
                    <div class="whois-item">
                        <div class="whois-label">Country</div>
                        <div class="whois-value">${contact.country || 'N/A'}</div>
                    </div>
                </div>
            </div>
        `;
    };
    
    return `
        <div class="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8 w-full h-full flex flex-col">
            <h3 class="text-2xl font-extrabold text-white mb-6">WHOIS Information</h3>
            <div class="whois-content">
                <!-- Domain Information -->
                <div class="whois-section">
                    <div class="whois-section-title text-blue-400">Domain Information</div>
                    <div class="whois-grid">
                        <div class="whois-item">
                            <div class="whois-label">Domain</div>
                            <div class="whois-value">${whoisData.domain || 'N/A'}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Status</div>
                            <div class="whois-value">${whoisData.status || 'N/A'}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Registrar</div>
                            <div class="whois-value">${whoisData.registrar?.name || 'N/A'}</div>
                        </div>
                        <div class="whois-item">
                            <div class="whois-label">Domain Age</div>
                            <div class="whois-value">${whoisData.domain_age ? `${whoisData.domain_age} days` : 'N/A'}</div>
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
                    <div class="whois-grid">
                        ${(whoisData.nameservers || []).map(ns => `
                            <div class="whois-item">
                                <div class="whois-value">${ns}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <!-- Registrant Information -->
                ${whoisData.registrant ? `
                    <div class="whois-section">
                        <div class="whois-section-title text-blue-400">Registrant Information</div>
                        ${formatContact(whoisData.registrant)}
                    </div>
                ` : ''}
                <!-- Admin Information -->
                ${whoisData.admin ? `
                    <div class="whois-section">
                        <div class="whois-section-title text-blue-400">Admin Information</div>
                        ${formatContact(whoisData.admin)}
                    </div>
                ` : ''}
                <!-- Tech Information -->
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

function createShodanCard(shodanData) {
    if (!shodanData) return '';
    
    return `
        <div class="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8 w-full h-full flex flex-col">
            <h3 class="text-2xl font-extrabold text-white mb-6">Shodan Information</h3>
            <div class="shodan-content">
                <!-- Basic Information -->
                <div class="shodan-section">
                    <div class="shodan-section-title text-blue-400">Basic Information</div>
                    <div class="shodan-grid">
                        <div class="shodan-item">
                            <div class="shodan-label">Organization</div>
                            <div class="shodan-value">${shodanData.organization || 'N/A'}</div>
                        </div>
                        <div class="shodan-item">
                            <div class="shodan-label">Operating System</div>
                            <div class="shodan-value">${shodanData.operating_system || 'N/A'}</div>
                        </div>
                    </div>
                </div>
                <!-- Services -->
                ${shodanData.services.length > 0 ? `
                    <div class="shodan-section">
                        <div class="shodan-section-title text-blue-400">Detected Services</div>
                        <div class="services-list" style="max-height: 300px; overflow-y: auto;">
                            ${shodanData.services.map(service => `
                                <div class="service-item">
                                    <div class="shodan-grid">
                                        <div>
                                            <div class="shodan-label">Service</div>
                                            <div class="shodan-value">${service.service}</div>
                                        </div>
                                        <div>
                                            <div class="shodan-label">Port</div>
                                            <div class="shodan-value">${service.port}</div>
                                        </div>
                                        <div>
                                            <div class="shodan-label">Product</div>
                                            <div class="shodan-value">${service.product || 'N/A'}</div>
                                        </div>
                                        <div>
                                            <div class="shodan-label">Version</div>
                                            <div class="shodan-value">${service.version || 'N/A'}</div>
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
                <!-- Ports -->
                ${shodanData.ports.length > 0 ? `
                    <div class="shodan-section">
                        <div class="shodan-section-title text-blue-400">Open Ports</div>
                        <div class="ports-list" style="max-height: 300px; overflow-y: auto;">
                            ${shodanData.ports.map(port => `
                                <div class="port-item">
                                    <div class="shodan-grid">
                                        <div>
                                            <div class="shodan-label">Port</div>
                                            <div class="shodan-value">${port.port}</div>
                                        </div>
                                        <div>
                                            <div class="shodan-label">Service</div>
                                            <div class="shodan-value">${port.service}</div>
                                        </div>
                                    </div>
                                    ${port.banner !== 'N/A' ? `
                                        <div class="banner-content">${port.banner}</div>
                                    ` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
                <!-- Vulnerabilities -->
                ${shodanData.vulnerabilities.length > 0 ? `
                    <div class="shodan-section">
                        <div class="shodan-section-title text-blue-400">Vulnerabilities</div>
                        <div class="vulnerabilities-list" style="max-height: 300px; overflow-y: auto;">
                            ${shodanData.vulnerabilities.map(vuln => `
                                <div class="vulnerability-item">
                                    <div class="shodan-grid">
                                        <div>
                                            <div class="shodan-label">ID</div>
                                            <div class="shodan-value">${vuln.id}</div>
                                        </div>
                                        <div>
                                            <div class="shodan-label">CVSS Score</div>
                                            <div class="shodan-value">${vuln.cvss}</div>
                                        </div>
                                    </div>
                                    <div class="mt-2">
                                        <div class="shodan-label">Summary</div>
                                        <div class="shodan-value">${vuln.summary}</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

// Export functions
function handleExportPDF() {
    if (window.lastCheckedData) {
        exportToPDF(window.lastCheckedData.ip, window.lastCheckedData.data);
    } else {
        alert('Please check an IP address first before exporting to PDF.');
    }
}

function exportToPDF(ip, data) {
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Add title
        doc.setFontSize(20);
        doc.text('IP Information Report', 20, 20);
        
        // Add IP address
        doc.setFontSize(14);
        doc.text(`IP Address: ${ip}`, 20, 30);
        
        // Add timestamp
        doc.setFontSize(10);
        doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 40);
        
        let y = 50;
        
        // Function to add section
        function addSection(title, data) {
            doc.setFontSize(12);
            doc.setFont(undefined, 'bold');
            doc.text(title, 20, y);
            y += 10;
            
            doc.setFont(undefined, 'normal');
            const tableData = Object.entries(data).map(([key, value]) => [
                key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                value || 'N/A'
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
        
        // Add sections
        if (data.abuse) {
            const { reports, ...abuseInfoNoReports } = data.abuse;
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
                'Organization': data.ipinfo.org || 'N/A',
                'Postal Code': data.ipinfo.postal || 'N/A',
                'Timezone': data.ipinfo.timezone || 'N/A'
            });
            
            if (data.ipinfo.asn) {
                addSection('ASN Information', {
                    'ASN': data.ipinfo.asn.asn || 'N/A',
                    'Name': data.ipinfo.asn.name || 'N/A',
                    'Domain': data.ipinfo.asn.domain || 'N/A',
                    'Route': data.ipinfo.asn.route || 'N/A',
                    'Type': data.ipinfo.asn.type || 'N/A'
                });
            }
            
            if (data.ipinfo.company) {
                addSection('Company Information', {
                    'Name': data.ipinfo.company.name || 'N/A',
                    'Domain': data.ipinfo.company.domain || 'N/A',
                    'Type': data.ipinfo.company.type || 'N/A'
                });
            }
            
            if (data.ipinfo.privacy) {
                addSection('Privacy Information', {
                    'VPN': data.ipinfo.privacy.vpn ? 'Yes' : 'No',
                    'Proxy': data.ipinfo.privacy.proxy ? 'Yes' : 'No',
                    'Tor': data.ipinfo.privacy.tor ? 'Yes' : 'No',
                    'Relay': data.ipinfo.privacy.relay ? 'Yes' : 'No',
                    'Hosting': data.ipinfo.privacy.hosting ? 'Yes' : 'No'
                });
            }
        }
        
        addSection('Security Information', {
            'VPN': data.security.vpn ? 'Yes' : 'No',
            'Proxy': data.security.proxy ? 'Yes' : 'No',
            'Tor': data.security.tor ? 'Yes' : 'No',
            'Relay': data.security.relay ? 'Yes' : 'No'
        });
        
        addSection('VPNAPI Location Data', {
            'City': data.location.city || 'N/A',
            'Region': data.location.region || 'N/A',
            'Country': data.location.country || 'N/A',
            'Continent': data.location.continent || 'N/A',
            'Latitude': data.location.latitude || 'N/A',
            'Longitude': data.location.longitude || 'N/A'
        });
        
        addSection('VPNAPI Network Data', {
            'Network': data.network.network || 'N/A',
            'ASN': data.network.autonomous_system_number || 'N/A',
            'Organization': data.network.autonomous_system_organization || 'N/A'
        });
        
        // Add footer
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.text(`Page ${i} of ${pageCount}`, 20, doc.internal.pageSize.height - 10);
            doc.text('Generated by IP Information Checker', doc.internal.pageSize.width - 20, doc.internal.pageSize.height - 10, { align: 'right' });
        }
        
        // Save the PDF
        doc.save(`IP_Report_${ip.replace(/\./g, '_')}.pdf`);
    } catch (error) {
        console.error('Error generating PDF:', error);
        alert('Error generating PDF. Please try again.');
    }
}

function handleExportScreenshot() {
    const grid = document.querySelector('.content-grid');
    if (!grid) {
        alert('No information to export. Please analyze an IP first.');
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
        link.download = 'ip_info_row.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
    });
}

// Navigation
function showSection(sectionId) {
    // Hide all sections with fade out
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('visible');
        section.style.display = 'none';
    });
    
    // Show selected section with fade in
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = 'block';
        setTimeout(() => {
            section.classList.add('visible');
        }, 10);
    }
    
    // Highlight active toolbar link
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
    
    // Store last selected section
    localStorage.setItem('lastSection', sectionId);
}

// Helper to get query parameters
function getQueryParam(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

function showProgressBar(label = 'Processing...') {
    const bar = document.getElementById('progress-bar');
    const labelEl = document.getElementById('progress-label');
    if (bar) bar.classList.remove('hidden');
    if (labelEl) labelEl.textContent = label;
    const inner = bar ? bar.querySelector('.progress-bar-inner') : null;
    if (inner) {
        inner.style.width = '100%';
        inner.classList.add('progress-bar-animated');
    }
}

function hideProgressBar() {
    const bar = document.getElementById('progress-bar');
    if (bar) bar.classList.add('hidden');
    const inner = bar ? bar.querySelector('.progress-bar-inner') : null;
    if (inner) {
        inner.style.width = '0%';
        inner.classList.remove('progress-bar-animated');
    }
}

// Helper to highlight the correct toolbar link based on path
function highlightToolbarLinkByPath(path) {
    document.querySelectorAll('.toolbar-link').forEach(link => {
        link.classList.remove('active');
    });
    if (path === '/ip') {
        document.querySelector('.toolbar-link[href="/ip"]')?.classList.add('active');
    } else if (path === '/domain') {
        document.querySelector('.toolbar-link[href="/domain"]')?.classList.add('active');
    } else if (path === '/url') {
        document.querySelector('.toolbar-link[href="/url"]')?.classList.add('active');
    }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    // Check current URL path and show appropriate section
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
        return; // Don't show any section on home page
    } else {
        // Show the appropriate section based on last selection
        const lastSection = localStorage.getItem('lastSection') || 'ip-section';
        showSection(lastSection);
        // Optionally highlight based on lastSection
        if (lastSection === 'domain-section') highlightToolbarLinkByPath('/domain');
        else if (lastSection === 'ip-section') highlightToolbarLinkByPath('/ip');
        else if (lastSection === 'url-section') highlightToolbarLinkByPath('/url');
    }

    // IP Form
    const ipForm = document.getElementById('ip-form');
    if (ipForm) {
        ipForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('ip-input').value.trim();
            if (!ip) return;
            const loading = document.getElementById('ip-loading');
            const results = document.getElementById('ip-results');
            // Clear all section results
            const vpnResults = document.getElementById('vpn-results');
            const geoNetworkResults = document.getElementById('geo-network-results');
            const abuseipdbResults = document.getElementById('abuseipdb-results');
            const alienvaultResults = document.getElementById('alienvault-results');
            const shodanResults = document.getElementById('shodan-results');
            if (vpnResults) vpnResults.innerHTML = '';
            if (geoNetworkResults) geoNetworkResults.innerHTML = '';
            if (abuseipdbResults) abuseipdbResults.innerHTML = '';
            if (alienvaultResults) alienvaultResults.innerHTML = '';
            if (shodanResults) shodanResults.innerHTML = '';
            if (loading) loading.classList.remove('hidden');
            showProgressBar('Analyzing IP address...');
            fetch('/check_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            })
            .then(res => res.json())
            .then(data => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                // --- VPN/Security Section ---
                if (vpnResults) {
                    vpnResults.innerHTML = '';
                    if (data.security) {
                        vpnResults.innerHTML += createInfoCard('VPNAPI.io VPN Checker', data.security);
                    }
                    if (data.ipinfo && data.ipinfo.privacy) {
                        vpnResults.innerHTML += createInfoCard('IPInfo.io Privacy Information', data.ipinfo.privacy);
                    }
                    if (data.proxycheck) {
                        vpnResults.innerHTML += createInfoCard('ProxyCheck', filterProxyCheckFields(data.proxycheck));
                    }
                }
                // --- Geo/Network Section ---
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
                    if (data.alienvault && data.alienvault.geo) {
                        geoNetworkResults.innerHTML += createInfoCard('AlienVault: Geo', data.alienvault.geo);
                    }
                }
                // --- AbuseIPDB Section ---
                if (abuseipdbResults) {
                    abuseipdbResults.innerHTML = '';
                    if (data.abuse) {
                        const { reports, ...abuseInfoNoReports } = data.abuse;
                        abuseipdbResults.innerHTML += createInfoCard('Abuse Info', abuseInfoNoReports);
                        if (reports && reports.length) {
                            abuseipdbResults.innerHTML += createAbuseReportsCard(reports);
                        }
                    }
                }
                // --- AlienVault Section ---
                if (alienvaultResults) {
                    alienvaultResults.innerHTML = '';
                    if (data.alienvault && typeof data.alienvault === 'object') {
                        const avSections = Object.entries(data.alienvault)
                            .filter(([k, v]) => v && typeof v === 'object' && k !== 'malware' && k !== 'http_scans' && k !== 'passive_dns' && k !== 'url_list');
                        if (avSections.length > 0) {
                            avSections.forEach(([section, sectionData]) => {
                                alienvaultResults.innerHTML += createInfoCard(
                                    `AlienVault: ${section.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`, 
                                    filterAlienVaultFields(sectionData, section)
                                );
                            });
                        }
                    }
                }
                // --- Shodan Section ---
                if (shodanResults) {
                    shodanResults.innerHTML = '';
                    if (data.shodan) {
                        shodanResults.innerHTML += createShodanCard(data.shodan);
                    }
                }
                if (results) results.classList.remove('hidden');
                runEqualizeAfterResults();
            })
            .catch(() => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                if (vpnResults) vpnResults.innerText = 'Error fetching IP data.';
                if (geoNetworkResults) geoNetworkResults.innerText = 'Error fetching IP data.';
                if (abuseipdbResults) abuseipdbResults.innerText = 'Error fetching IP data.';
                if (alienvaultResults) alienvaultResults.innerText = 'Error fetching IP data.';
                if (shodanResults) shodanResults.innerText = 'Error fetching IP data.';
            });
        });
    }

    // Domain Form
    const domainForm = document.getElementById('domain-form');
    if (domainForm) {
        domainForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const domain = document.getElementById('domain-input').value.trim();
            if (!domain) return;
            const loading = document.getElementById('domain-loading');
            const results = document.getElementById('domain-results');
            if (results) results.innerHTML = '';
            if (loading) loading.classList.remove('hidden');
            showProgressBar('Analyzing domain...');
            fetch('/check_domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            })
            .then(res => res.json())
            .then(data => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                if (results) {
                    results.innerHTML = '';
                    // WHOIS
                    if (data.whois) {
                        results.innerHTML += createWhoisCard(data.whois);
                    }
                    // DNS Records
                    if (data.dns_records) {
                        results.innerHTML += createInfoCard('DNS Records', data.dns_records);
                    }
                    // SSL Info
                    if (data.ssl_info) {
                        results.innerHTML += createInfoCard('SSL Certificate', data.ssl_info);
                    }
                    if (results) results.classList.remove('hidden');
                }
            })
            .catch(() => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                if (results) results.innerText = 'Error fetching domain data.';
            });
        });
    }

    // URL Form
    const urlForm = document.getElementById('url-form');
    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const url = document.getElementById('url-input').value.trim();
            if (!url) return;
            const loading = document.getElementById('url-loading');
            const results = document.getElementById('url-results');
            if (results) results.innerHTML = '';
            if (loading) loading.classList.remove('hidden');
            showProgressBar('Analyzing URL...');
            fetch('/analyze_url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            })
            .then(res => res.json())
            .then(data => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                if (results) {
                    results.innerHTML = '';
                    if (data.url_analysis) {
                        // URL Structure
                        if (data.url_analysis.parsed_url) {
                            results.innerHTML += createInfoCard('URL Structure', data.url_analysis.parsed_url);
                        }
                        // Response Info
                        if (data.url_analysis.response) {
                            results.innerHTML += createInfoCard('Response Information', data.url_analysis.response);
                        }
                        // Security Headers
                        if (data.url_analysis.security_headers) {
                            results.innerHTML += createInfoCard('Security Headers', data.url_analysis.security_headers);
                        }
                        // Technology Stack
                        if (data.url_analysis.technologies) {
                            results.innerHTML += createInfoCard('Technology Stack', data.url_analysis.technologies);
                        }
                        // Intezer Analysis
                        if (data.url_analysis.intezer_analysis) {
                            results.innerHTML += createInfoCard('Intezer Analysis', data.url_analysis.intezer_analysis);
                        }
                    }
                    if (results) results.classList.remove('hidden');
                }
            })
            .catch(() => {
                if (loading) loading.classList.add('hidden');
                hideProgressBar();
                if (results) results.innerText = 'Error fetching URL data.';
            });
        });
    }
});

// Add equalizeRowHeights and runEqualizeAfterResults at the end of the file
function equalizeRowHeights() {
    document.querySelectorAll('.results-row').forEach(row => {
        // Reset heights first
        row.querySelectorAll('.info-card, .whois-card, .shodan-card').forEach(card => {
            card.style.height = 'auto';
        });
        // Find max height
        let maxHeight = 0;
        row.querySelectorAll('.info-card, .whois-card, .shodan-card').forEach(card => {
            maxHeight = Math.max(maxHeight, card.offsetHeight);
        });
        // Set all to max height
        row.querySelectorAll('.info-card, .whois-card, .shodan-card').forEach(card => {
            card.style.height = maxHeight + 'px';
        });
    });
}
function runEqualizeAfterResults() {
    setTimeout(equalizeRowHeights, 100);
}
window.runEqualizeAfterResults = runEqualizeAfterResults;

// Helper to filter ProxyCheck fields
function filterProxyCheckFields(data) {
    const exclude = [
        'currency', 'devices', 'isocode', 'continent', 'continentcode', 'regioncode', 'organisation', 'latitude', 'longitude', 'postcode'
    ];
    return Object.fromEntries(Object.entries(data).filter(([key]) => !exclude.includes(key.toLowerCase())));
}

// Helper to filter AlienVault fields
function filterAlienVaultFields(data, section) {
    if (section === 'general') {
        const exclude = [
            'accuracy_radius', 'area_code', 'base_indicator', 'charset', 'city_data', 
            'continent_code', 'country_code2', 'country_code3', 'dma_code', 'false_positive', 
            'flag_title', 'flag_url', 'latitude', 'longitude', 'pulse_info', 'sections', 
            'type_title', 'validation'
        ];
        return Object.fromEntries(Object.entries(data).filter(([key]) => !exclude.includes(key.toLowerCase())));
    }
    if (section === 'geo') {
        const exclude = [
            'accuracy_radius', 'area_code', 'charset', 'city_data', 'continent_code', 
            'country_code2', 'country_code 2', 'country_code3', 'country_code 3', 'dma_code', 
            'flag_title', 'flag_url', 'latitude', 'longitude'
        ];
        return Object.fromEntries(Object.entries(data).filter(([key]) => !exclude.includes(key.toLowerCase())));
    }
    return data;
} 