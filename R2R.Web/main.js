const API_BASE = 'http://localhost:5258';

// Global state
let state = {
    sessionId: null,
    targetId: null,
    targetIp: null,
    targetOs: null,
    phase: 'reconnaissance',
    ports: [],
    allHosts: [], // Store all discovered hosts
    hostContexts: {} // Store context per host: { "192.168.1.10": { username: "...", ... } }
};

// Utility functions
function showStatus(message, type = 'success') {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = `status show ${type}`;
    setTimeout(() => {
        status.classList.remove('show');
    }, 3000);
}

window.goToScreen = function(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(screenId).classList.add('active');
    
    // Update sub-nav active state if it exists on this screen
    const activeScreen = document.getElementById(screenId);
    const subNav = activeScreen.querySelector('.sub-nav');
    if (subNav) {
        subNav.querySelectorAll('a').forEach(link => {
            link.classList.remove('active');
            // Check if this link points to the current screen
            if (link.getAttribute('onclick').includes(screenId)) {
                link.classList.add('active');
            }
        });
    }
}

// Screen 1: Create Session & Target
document.getElementById('create-session-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const sessionName = document.getElementById('session-name').value;
    const targetIp = document.getElementById('target-ip').value;
    const targetOs = document.getElementById('target-os').value;
    
    try {
        // Create session
        const sessionRes = await fetch(`${API_BASE}/sessions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: sessionName })
        });
        
        if (!sessionRes.ok) throw new Error('Failed to create session');
        
        const session = await sessionRes.json();
        state.sessionId = session.id;
        
        // Create target
        const targetRes = await fetch(`${API_BASE}/targets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sessionId: session.id,
                ip: targetIp,
                os: targetOs
            })
        });
        
        if (!targetRes.ok) throw new Error('Failed to create target');
        
        const target = await targetRes.json();
        state.targetId = target.id;
        state.targetIp = targetIp;
        state.targetOs = targetOs;
        
        showStatus(`Session "${sessionName}" created successfully!`);
        
        // Fetch Nmap suggestions
        await fetchNmapSuggestions();
        goToScreen('nmap-suggestions');
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
});

// Screen 2: Fetch and display Nmap suggestions
async function fetchNmapSuggestions() {
    try {
        const res = await fetch(`${API_BASE}/nmap/suggest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip: state.targetIp,
                os: state.targetOs
            })
        });
        
        if (!res.ok) throw new Error('Failed to fetch Nmap suggestions');
        
        const commands = await res.json();
        displayNmapCommands(commands);
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

function displayNmapCommands(commands) {
    const commandsList = document.getElementById('nmap-commands-list');
    
    commandsList.innerHTML = commands.map(cmd => `
        <div class="nmap-command-card">
            <h3>${cmd.title}</h3>
            ${cmd.command && cmd.command !== 'N/A' ? `
                <div class="nmap-command-syntax" data-command="${cmd.command.replace(/"/g, '&quot;')}" title="Click to copy">
                    ${cmd.command}
                </div>
            ` : ''}
            <div class="nmap-command-description">${cmd.explanation}</div>
        </div>
    `).join('');
    
    // Add click listeners after rendering
    document.querySelectorAll('.nmap-command-syntax').forEach(el => {
        el.addEventListener('click', () => {
            const text = el.getAttribute('data-command');
            copyToClipboard(text, el);
        });
    });
}

function copyToClipboard(text, element) {
    navigator.clipboard.writeText(text).then(() => {
        const originalBg = element.style.background;
        element.style.background = '#d1fae5';
        showStatus('Copied to clipboard!');
        setTimeout(() => {
            element.style.background = originalBg;
        }, 500);
    }).catch(() => {
        // Fallback: try the old execCommand method
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showStatus('Copied to clipboard!');
            const originalBg = element.style.background;
            element.style.background = '#d1fae5';
            setTimeout(() => {
                element.style.background = originalBg;
            }, 500);
        } catch (fallbackErr) {
            showStatus('Copy failed. Please copy manually.', 'error');
        }
        document.body.removeChild(textarea);
    });
}

// Screen 3: Parse Nmap XML
document.getElementById('nmap-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const nmapXml = document.getElementById('nmap-xml').value;
    
    try {
        const res = await fetch(`${API_BASE}/targets/${state.targetId}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nmapOutput: nmapXml })
        });
        
        if (!res.ok) {
            const errorText = await res.text();
            throw new Error('Failed to parse Nmap output');
        }
        
        const data = await res.json();
        
        // Handle multiple hosts vs single host response
        if (data.discoveredTargets && data.discoveredTargets.length > 0) {
            // Multiple hosts detected - store all of them
            state.allHosts = data.discoveredTargets;
            // Use first host as default for attack suggestions
            state.targetId = data.discoveredTargets[0].targetId;
            state.ports = data.discoveredTargets[0].ports || [];
            showStatus(`${data.hostCount} hosts detected!`);
        } else {
            // Single host - wrap it in the same structure for consistency
            state.allHosts = [{
                targetId: data.targetId,
                ipAddress: state.targetIp,
                hostname: null,
                portsDetected: data.portsDetected,
                ports: data.ports || []
            }];
            state.ports = data.ports || [];
            showStatus('Nmap scan parsed successfully!');
        }
        
        displayPorts();
        goToScreen('parsed-ports');
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
});

// Screen 4: Display parsed ports
function displayPorts() {
    const portsList = document.getElementById('ports-list');
    
    if (state.allHosts.length === 0) {
        portsList.innerHTML = '<div class="empty-state"><h3>No ports detected</h3><p>Try pasting valid Nmap XML output</p></div>';
        return;
    }
    
    // Display all hosts with nested ports
    portsList.innerHTML = state.allHosts.map((host, index) => `
        <div class="host-card">
            <div class="host-header">
                <h3>${host.ipAddress}${host.hostname ? ` (${host.hostname})` : ''}</h3>
                <span class="port-count">${host.portsDetected} port${host.portsDetected !== 1 ? 's' : ''}</span>
            </div>
            <div class="ports-container">
                ${host.ports.length > 0 ? host.ports.map(port => `
                    <div class="port-item">
                        <span class="port-number">${port.number}<span class="port-protocol">/${port.protocol}</span></span>
                        <span class="port-service">${port.service || 'unknown'}${port.version ? ` (${port.version})` : ''}</span>
                    </div>
                `).join('') : '<p class="no-ports">No open ports detected</p>'}
            </div>
            <div class="host-actions">
                <button class="btn btn-primary btn-host-vectors" data-host-index="${index}">
                    Get Attack Vectors for ${host.ipAddress}
                </button>
            </div>
        </div>
    `).join('');
    
    // Add click handlers for host-specific attack vector buttons
    document.querySelectorAll('.btn-host-vectors').forEach(btn => {
        btn.addEventListener('click', function() {
            const hostIndex = parseInt(this.getAttribute('data-host-index'));
            getSuggestionsForHost(hostIndex);
        });
    });
    
    // Update hosts page dropdown
    updateHostsDropdown();
}

// Get attack suggestions for a specific host
async function getSuggestionsForHost(hostIndex) {
    const host = state.allHosts[hostIndex];
    
    if (!host) {
        showStatus('Host not found', 'error');
        return;
    }
    
    // Get saved context for this host
    const context = state.hostContexts[host.ipAddress] || {};
    
    // Build acquiredItems based on what context we have
    const acquiredItems = [];
    if (context.username) acquiredItems.push('username');
    if (context.password) acquiredItems.push('password');
    if (context.hash) acquiredItems.push('hash');
    if (context.domain) acquiredItems.push('domain_info');
    
    try {
        const res = await fetch(`${API_BASE}/attack-paths/suggest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                currentPhase: state.phase,
                acquiredItems: acquiredItems, // Now includes context-based items
                openPorts: host.ports.map(p => p.number),
                services: host.ports.map(p => p.service).filter(s => s && s !== 'unknown'),
                targetOS: context.osVersion || state.targetOs, // Use context OS if available
                targetIp: host.ipAddress,
                domainName: context.domain || null, // Include domain from context
                sessionId: state.sessionId
            })
        });
        
        if (!res.ok) throw new Error('Failed to get suggestions');
        
        const data = await res.json();
        
        // Store the current host's IP for display
        state.currentHostIp = host.ipAddress;
        
        // Update the target host display
        const hostDisplay = document.getElementById('target-host-display');
        hostDisplay.textContent = `Target: ${host.ipAddress}`;
        hostDisplay.style.display = 'block';
        
        displaySuggestions(data.applicableVectors || []);
        goToScreen('suggestions');
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

// Screen 5: Get attack suggestions (legacy - for backward compatibility)
window.getSuggestions = async function() {
    try {
        const res = await fetch(`${API_BASE}/attack-paths/suggest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                currentPhase: state.phase,
                acquiredItems: [],
                openPorts: state.ports.map(p => p.number),
                services: state.ports.map(p => p.service).filter(s => s && s !== 'unknown'),
                targetOS: state.targetOs,
                targetIp: state.targetIp,
                sessionId: state.sessionId
            })
        });
        
        if (!res.ok) throw new Error('Failed to get suggestions');
        
        const data = await res.json();
        
        // Hide the target host display for legacy calls
        const hostDisplay = document.getElementById('target-host-display');
        hostDisplay.style.display = 'none';
        
        displaySuggestions(data.applicableVectors || []);
        goToScreen('suggestions');
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

window.updatePhase = async function() {
    state.phase = document.getElementById('phase-select').value;
    
    // If we have a current host IP, refresh suggestions for that specific host
    if (state.currentHostIp) {
        const hostIndex = state.allHosts.findIndex(h => h.ipAddress === state.currentHostIp);
        if (hostIndex !== -1) {
            await getSuggestionsForHost(hostIndex);
            return;
        }
    }
    
    // Otherwise fall back to legacy behavior
    await getSuggestions();
}

function displaySuggestions(vectors) {
    const suggestionsList = document.getElementById('suggestions-list');
    
    if (vectors.length === 0) {
        suggestionsList.innerHTML = '<div class="empty-state"><h3>No suggestions available</h3><p>Try changing the phase or scanning more ports</p></div>';
        return;
    }
    
    // Group vectors by service
    const grouped = vectors.reduce((acc, vector) => {
        const service = vector.service || 'General';
        if (!acc[service]) {
            acc[service] = [];
        }
        acc[service].push(vector);
        return acc;
    }, {});
    
    // Render grouped vectors
    suggestionsList.innerHTML = Object.entries(grouped)
        .map(([service, serviceVectors]) => `
            <div class="service-group">
                <h2 class="service-heading">${service}</h2>
                <div class="service-vectors">
                    ${serviceVectors.map(vector => `
                        <div class="vector-card">
                            <h3>${vector.name}</h3>
                            ${vector.commands.map(cmd => `
                                <div class="command-item">
                                    <div class="command-tool">${cmd.tool}</div>
                                    <div class="command-syntax" data-command="${escapeHtml(cmd.readyCommand)}">${cmd.readyCommand}</div>
                                </div>
                            `).join('')}
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('');
    
    // Add click handlers for clipboard functionality
    document.querySelectorAll('.command-syntax').forEach(el => {
        el.addEventListener('click', function() {
            const command = this.getAttribute('data-command');
            copyToClipboard(command, this);
        });
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Screen 6: Reference / Dictionary Mode
window.loadReferenceVectors = async function() {
    const phase = document.getElementById('reference-phase-select').value;
    
    try {
        const res = await fetch(`${API_BASE}/attack-paths/all?phase=${phase}`, {
            method: 'GET'
        });
        
        if (!res.ok) throw new Error('Failed to load reference vectors');
        
        const data = await res.json();
        displayReferenceVectors(data.vectors || []);
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

function displayReferenceVectors(vectors) {
    const referenceList = document.getElementById('reference-list');
    
    if (vectors.length === 0) {
        referenceList.innerHTML = '<div class="empty-state"><h3>No vectors found for this phase</h3></div>';
        return;
    }
    
    // Group by service (same as suggestions page)
    const grouped = vectors.reduce((acc, vector) => {
        const service = vector.service || 'General';
        if (!acc[service]) {
            acc[service] = [];
        }
        acc[service].push(vector);
        return acc;
    }, {});
    
    // Render with raw syntax (no variable substitution)
    referenceList.innerHTML = Object.entries(grouped)
        .map(([service, serviceVectors]) => `
            <div class="service-group">
                <h2 class="service-heading">${service}</h2>
                <div class="service-vectors">
                    ${serviceVectors.map(vector => `
                        <div class="vector-card">
                            <h3>${vector.name}</h3>
                            ${vector.description ? `<p class="vector-description">${vector.description}</p>` : ''}
                            ${vector.commands.map(cmd => `
                                <div class="command-item">
                                    <div class="command-tool">${cmd.tool}</div>
                                    <div class="command-syntax-raw">${cmd.syntax}</div>
                                    ${cmd.description ? `<div class="command-desc">${cmd.description}</div>` : ''}
                                </div>
                            `).join('')}
                            ${vector.prerequisites && vector.prerequisites.length > 0 ? `
                                <div class="prerequisites">
                                    <strong>Prerequisites:</strong> ${vector.prerequisites.join(', ')}
                                </div>
                            ` : ''}
                            ${vector.possibleOutcomes && vector.possibleOutcomes.length > 0 ? `
                                <div class="outcomes">
                                    <strong>Possible Outcomes:</strong> ${vector.possibleOutcomes.join(', ')}
                                </div>
                            ` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('');
}

// Screen 6: Hosts Management Page
function updateHostsDropdown() {
    const select = document.getElementById('host-select');
    const noHostsDiv = document.getElementById('no-hosts-available');
    
    if (state.allHosts.length === 0) {
        select.innerHTML = '<option value="">-- No hosts available --</option>';
        noHostsDiv.style.display = 'block';
        return;
    }
    
    noHostsDiv.style.display = 'none';
    select.innerHTML = '<option value="">-- Select a host --</option>' +
        state.allHosts.map((host, index) => 
            `<option value="${index}">${host.ipAddress}${host.hostname ? ` (${host.hostname})` : ''}</option>`
        ).join('');
}

// Load host information when selected
window.loadHostInfo = function() {
    const selectedIndex = document.getElementById('host-select').value;
    const container = document.getElementById('host-info-container');
    
    if (!selectedIndex || selectedIndex === '') {
        container.style.display = 'none';
        return;
    }
    
    container.style.display = 'block';
    
    const host = state.allHosts[parseInt(selectedIndex)];
    const context = state.hostContexts[host.ipAddress] || {};
    
    // Populate readonly fields from scan
    document.getElementById('host-ip').value = host.ipAddress || '';
    document.getElementById('host-hostname').value = host.hostname || 'N/A';
    document.getElementById('host-ports-count').value = `${host.portsDetected} port(s) open`;
    
    // Populate editable fields from context or leave empty
    document.getElementById('host-os').value = context.osVersion || '';
    document.getElementById('host-username').value = context.username || '';
    document.getElementById('host-password').value = context.password || '';
    document.getElementById('host-domain').value = context.domain || '';
    document.getElementById('host-hash').value = context.hash || '';
    document.getElementById('host-notes').value = context.notes || '';
}

// Save host information
window.saveHostInfo = function() {
    const selectedIndex = document.getElementById('host-select').value;
    
    if (!selectedIndex || selectedIndex === '') {
        showStatus('Please select a host first', 'error');
        return;
    }
    
    const host = state.allHosts[parseInt(selectedIndex)];
    
    state.hostContexts[host.ipAddress] = {
        osVersion: document.getElementById('host-os').value,
        username: document.getElementById('host-username').value,
        password: document.getElementById('host-password').value,
        domain: document.getElementById('host-domain').value,
        hash: document.getElementById('host-hash').value,
        notes: document.getElementById('host-notes').value
    };
    
    showStatus(`Information saved for ${host.ipAddress}`);
}

// Initialize
