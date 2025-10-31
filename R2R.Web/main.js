const API_BASE = 'http://localhost:5258';

// Global state
let state = {
    sessionId: null,
    targetId: null,
    targetIp: null,
    targetOs: null,
    phase: 'reconnaissance',
    ports: [],
    allHosts: [] // Store all discovered hosts
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
    portsList.innerHTML = state.allHosts.map(host => `
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
        </div>
    `).join('');
}

// Screen 5: Get attack suggestions
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
        displaySuggestions(data.applicableVectors || []);
        goToScreen('suggestions');
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

window.updatePhase = async function() {
    state.phase = document.getElementById('phase-select').value;
    await getSuggestions();
}

function displaySuggestions(vectors) {
    const suggestionsList = document.getElementById('suggestions-list');
    
    if (vectors.length === 0) {
        suggestionsList.innerHTML = '<div class="empty-state"><h3>No suggestions available</h3><p>Try changing the phase or scanning more ports</p></div>';
        return;
    }
    
    suggestionsList.innerHTML = vectors.map(vector => `
        <div class="vector-card">
            <h3>${vector.name}</h3>
            ${vector.commands.map(cmd => `
                <div class="command-item">
                    <div class="command-tool">${cmd.tool}</div>
                    <div class="command-syntax">${cmd.readyCommand}</div>
                </div>
            `).join('')}
        </div>
    `).join('');
}

// Initialize
