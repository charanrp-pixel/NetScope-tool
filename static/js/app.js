(function () {
  const cidrEl = document.getElementById('cidr');
  const useLocalBtn = document.getElementById('use-local');
  const portScanEl = document.getElementById('port-scan');
  const btnScan = document.getElementById('btn-scan');
  const scanStatus = document.getElementById('scan-status');
  const deviceTbody = document.getElementById('device-tbody');
  const btnExportPdf = document.getElementById('btn-export-pdf');

  let lastDevices = [];
  let lastCidr = null;
  let topologyNetwork = null;
  let blockedIps = [];
  let monitoredIps = [];
  let currentTrafficIp = null;

  window.toggleBlock = async function(ip, action) {
    try {
      const res = await fetch('/api/block-device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action })
      });
      const data = await res.json();
      if (!data.success) {
        alert("Error: " + data.error);
        return;
      }
      blockedIps = data.blocked_ips || [];
      renderDevices(lastDevices);
      if (currentModalIp === ip) {
        const btn = document.getElementById('modal-block-btn');
        const isBlockedNow = blockedIps.includes(ip);
        btn.textContent = isBlockedNow ? 'Unblock Device' : 'Block Device';
        btn.className = isBlockedNow ? 'btn btn-secondary' : 'btn btn-primary';
      }
    } catch(e) {
      alert("Error: " + e.message);
    }
  };

  let currentModalIp = null;
  
  window.closeModal = function() {
    document.getElementById('device-modal').style.display = 'none';
    currentModalIp = null;
  };
  
  window.toggleBlockFromModal = function() {
    if(!currentModalIp) return;
    const isBlocked = blockedIps.includes(currentModalIp);
    toggleBlock(currentModalIp, isBlocked ? 'unblock' : 'block');
  };

  window.toggleMonitorFromModal = async function() {
    if(!currentModalIp) return;
    const isMonitored = monitoredIps.includes(currentModalIp);
    if (isMonitored) {
      await stopTrafficMonitor(currentModalIp);
    } else {
      await startTrafficMonitor(currentModalIp);
    }
    updateModalMonitorButton();
  };

  async function startTrafficMonitor(ip) {
    try {
      const res = await fetch('/api/start-traffic-monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (!data.success) {
        alert("Error: " + data.error);
        return false;
      }
      monitoredIps.push(ip);
      updateMonitoredDevicesList();
      return true;
    } catch(e) {
      alert("Error: " + e.message);
      return false;
    }
  }

  async function stopTrafficMonitor(ip) {
    try {
      const res = await fetch('/api/stop-traffic-monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (!data.success) {
        alert("Error: " + data.error);
        return false;
      }
      monitoredIps = monitoredIps.filter(mip => mip !== ip);
      updateMonitoredDevicesList();
      if (currentTrafficIp === ip) {
        hideTrafficData();
      }
      return true;
    } catch(e) {
      alert("Error: " + e.message);
      return false;
    }
  }

  function updateModalMonitorButton() {
    if (!currentModalIp) return;
    const btn = document.getElementById('modal-monitor-btn');
    const isMonitored = monitoredIps.includes(currentModalIp);
    btn.textContent = isMonitored ? 'Stop Monitoring' : 'Monitor Traffic';
    btn.className = isMonitored ? 'btn btn-secondary' : 'btn btn-primary';
  }

  function updateMonitoredDevicesList() {
    const container = document.getElementById('monitored-devices-list');
    if (monitoredIps.length === 0) {
      container.innerHTML = '<p>No devices currently being monitored.</p>';
      return;
    }
    
    container.innerHTML = '<h4>Monitored Devices:</h4>' + monitoredIps.map(ip => 
      `<div class="monitored-device">
        <span>${ip}</span>
        <button class="btn btn-ghost btn-sm" onclick="viewTrafficData('${ip}')">View Data</button>
        <button class="btn btn-ghost btn-sm" onclick="stopTrafficMonitor('${ip}')">Stop</button>
      </div>`
    ).join('');
  }

  window.viewTrafficData = function(ip) {
    currentTrafficIp = ip;
    loadTrafficData(ip);
    document.getElementById('traffic-data').style.display = 'block';
    document.getElementById('traffic-ip').textContent = ip;
  };

  function hideTrafficData() {
    document.getElementById('traffic-data').style.display = 'none';
    currentTrafficIp = null;
  }

  async function loadTrafficData(ip) {
    try {
      const res = await fetch(`/api/traffic-data/${ip}`);
      const data = await res.json();
      
      if (res.status === 404) {
        document.getElementById('total-packets').textContent = '0';
        document.getElementById('total-bytes').textContent = '0';
        document.getElementById('packets-per-sec').textContent = '0';
        document.getElementById('bytes-per-sec').textContent = '0';
        document.getElementById('protocol-stats').innerHTML = '<p>No data available yet.</p>';
        document.getElementById('packet-list').innerHTML = '<p>No packets captured yet.</p>';
        return;
      }
      
      // Update statistics
      document.getElementById('total-packets').textContent = data.total_packets || 0;
      document.getElementById('total-bytes').textContent = formatBytes(data.total_bytes || 0);
      document.getElementById('packets-per-sec').textContent = (data.packets_per_second || 0).toFixed(2);
      document.getElementById('bytes-per-sec').textContent = formatBytes(data.bytes_per_second || 0) + '/s';
      
      // Update protocol breakdown
      const protocolStats = document.getElementById('protocol-stats');
      const protocols = data.protocols || {};
      protocolStats.innerHTML = Object.entries(protocols).map(([protocol, count]) => 
        `<div class="protocol-item">
          <span class="protocol-name">${protocol}</span>
          <span class="protocol-count">${count}</span>
        </div>`
      ).join('');
      
      // Update recent packets
      const packetList = document.getElementById('packet-list');
      const packets = data.recent_packets || [];
      packetList.innerHTML = packets.slice(-10).reverse().map(packet => 
        `<div class="packet-item">
          <span class="packet-time">${new Date(packet.timestamp * 1000).toLocaleTimeString()}</span>
          <span class="packet-info">${packet.src_ip}:${packet.src_port || 'N/A'} → ${packet.dst_ip}:${packet.dst_port || 'N/A'}</span>
          <span class="packet-protocol">${packet.protocol}</span>
          <span class="packet-size">${formatBytes(packet.size)}</span>
        </div>`
      ).join('');
      
    } catch(e) {
      console.error('Error loading traffic data:', e);
    }
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  window.openDeviceModal = async function(ip) {
    const device = lastDevices.find(d => d.ip === ip);
    if(!device) return;
    
    currentModalIp = ip;
    document.getElementById('device-modal').style.display = 'flex';
    document.getElementById('modal-status').style.display = 'block';
    document.getElementById('modal-details').style.display = 'none';
    document.getElementById('modal-status').textContent = 'Loading extensive details...';
    
    const btn = document.getElementById('modal-block-btn');
    const isBlocked = blockedIps.includes(ip);
    btn.textContent = isBlocked ? 'Unblock Device' : 'Block Device';
    btn.className = isBlocked ? 'btn btn-secondary' : 'btn btn-primary';

    try {
      const res = await fetch('/api/device-details', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(device) // send what we have
      });
      const data = await res.json();
      if(data.error) throw new Error(data.error);
      
      document.getElementById('modal-status').style.display = 'none';
      document.getElementById('modal-details').style.display = 'block';
      
      document.getElementById('md-ip').textContent = data.ip;
      document.getElementById('md-mac').textContent = data.mac;
      document.getElementById('md-vendor').textContent = data.vendor;
      document.getElementById('md-type').textContent = data.device_type;
      document.getElementById('md-os').textContent = data.os;
      
      const isBlockedNow = data.is_blocked;
      btn.textContent = isBlockedNow ? 'Unblock Device' : 'Block Device';
      btn.className = isBlockedNow ? 'btn btn-secondary' : 'btn btn-primary';
      
      updateModalMonitorButton();
      
      const sList = document.getElementById('md-services');
      if(!data.services || data.services.length === 0) {
        sList.innerHTML = '<li>No open/known ports detected.</li>';
      } else {
        sList.innerHTML = data.services.map(s => {
          return '<li><strong>Port ' + s.port + '</strong>: ' + escapeHtml(s.name) + 
                 (s.banner ? '<br><span style="color:var(--text-muted);font-size:0.8rem">' + escapeHtml(s.banner) + '</span>' : '') + '</li>';
        }).join('');
      }
    } catch(e) {
      document.getElementById('modal-status').textContent = 'Error loading details: ' + e.message;
    }
  };

  useLocalBtn.addEventListener('click', async function () {
    try {
      const bRes = await fetch('/api/blocked-devices');
      const bData = await bRes.json();
      blockedIps = bData.blocked_ips || [];
      
      const r = await fetch('/api/network-info');
      const d = await r.json();
      if (d.cidr) cidrEl.value = d.cidr;
      if (d.ip) scanStatus.textContent = 'Using network: ' + d.cidr;
    } catch (e) {
      scanStatus.textContent = 'Could not get network info.';
    }
  });

  btnScan.addEventListener('click', async function () {
    btnScan.disabled = true;
    scanStatus.textContent = 'Scanning…';
    deviceTbody.innerHTML = '<tr><td colspan="8" class="empty-row">Scanning…</td></tr>';
    try {
      const cidr = cidrEl.value.trim() || null;
      const body = { port_scan: portScanEl.checked };
      if (cidr) body.cidr = cidr;
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed');
      lastDevices = data.devices || [];
      lastCidr = data.cidr || cidr;
      renderDevices(lastDevices);
      if (lastDevices.length) {
        scanStatus.textContent = 'Found ' + lastDevices.length + ' device(s).' + (data.message ? ' ' + data.message : '');
      } else {
        scanStatus.textContent = data.message || 'No devices found.';
      }
      await loadTopology();
    } catch (e) {
      scanStatus.textContent = 'Error: ' + e.message;
      deviceTbody.innerHTML = '<tr><td colspan="8" class="empty-row">Scan failed.</td></tr>';
    } finally {
      btnScan.disabled = false;
    }
  });

  function riskClass(risk) {
    if (!risk) return 'risk-low';
    return 'risk-' + risk.toLowerCase();
  }

  function renderDevices(devices) {
    if (!devices.length) {
      deviceTbody.innerHTML = '<tr><td colspan="8" class="empty-row">No devices found.</td></tr>';
      return;
    }
    deviceTbody.innerHTML = devices.map(function (d) {
      const risk = d.risk || 'low';
      const ports = (d.open_ports || []).join(', ') || '—';
      const name = d.device_name || '—';
      const vendor = d.vendor || '—';
      const sent = d.packets_sent != null ? d.packets_sent : '—';
      const recv = d.packets_received != null ? d.packets_received : '—';
      const isBlocked = blockedIps.includes(d.ip);
      const actionBtn = '<button type="button" class="btn btn-ghost btn-sm" onclick="openDeviceModal(\'' + d.ip + '\')">Details</button>';
      
      return (
        '<tr>' +
        '<td>' + escapeHtml(d.ip) + '</td>' +
        '<td>' + escapeHtml(d.mac) + '</td>' +
        '<td>' + escapeHtml(name) + '</td>' +
        '<td>' + escapeHtml(vendor) + '</td>' +
        '<td><span class="risk-badge ' + riskClass(risk) + '">' + escapeHtml(risk) + '</span></td>' +
        '<td>' + escapeHtml(ports) + '</td>' +
        '<td>' + sent + ' / ' + recv + '</td>' +
        '<td>' + actionBtn + '</td>' +
        '</tr>'
      );
    }).join('');
  }

  function escapeHtml(s) {
    if (s == null) return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  async function loadTopology() {
    try {
      const res = await fetch('/api/topology');
      const data = await res.json();
      const container = document.getElementById('topology-container');
      if (!container || !window.vis) return;
      const nodes = new vis.DataSet((data.nodes || []).map(function (n) {
        return {
          id: n.id,
          label: n.label,
          group: n.group,
          title: n.mac ? 'MAC: ' + n.mac + (n.risk ? '\nRisk: ' + n.risk : '') : undefined,
        };
      }));
      const edges = new vis.DataSet(data.edges || []);
      const opts = {
        nodes: {
          font: { color: '#e8e8ed', face: 'Outfit' },
          borderWidth: 2,
          shape: 'dot',
        },
        groups: {
          gateway: { color: { background: '#f59e0b', border: '#b45309' }, size: 28 },
          device: { color: { background: '#2a2a36', border: '#4b5563' }, size: 22 },
          medium: { color: { background: '#eab308', border: '#a16207' }, size: 22 },
          high: { color: { background: '#ef4444', border: '#b91c1c' }, size: 22 },
        },
        edges: { color: { color: '#4b5563' } },
        physics: { enabled: true, barnesHut: { gravitationalConstant: -4000, springLength: 120 } },
      };
      const netData = { nodes, edges };
      if (topologyNetwork) topologyNetwork.destroy();
      topologyNetwork = new vis.Network(container, netData, opts);
    } catch (e) {
      console.warn('Topology load failed', e);
    }
  }

  btnExportPdf.addEventListener('click', async function () {
    btnExportPdf.disabled = true;
    try {
      const body = { devices: lastDevices, cidr: lastCidr };
      const res = await fetch('/api/export-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'netscope_scan_report.pdf';
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      alert('Export failed: ' + e.message);
    } finally {
      btnExportPdf.disabled = false;
    }
  });

  // Traffic monitoring event listeners
  document.getElementById('btn-refresh-monitored').addEventListener('click', async function() {
    try {
      const res = await fetch('/api/monitored-devices');
      const data = await res.json();
      monitoredIps = data.monitored_ips || [];
      updateMonitoredDevicesList();
    } catch(e) {
      console.error('Error refreshing monitored devices:', e);
    }
  });

  document.getElementById('btn-stop-monitor').addEventListener('click', function() {
    if (currentTrafficIp) {
      stopTrafficMonitor(currentTrafficIp);
    }
  });

  document.getElementById('btn-clear-data').addEventListener('click', async function() {
    if (!currentTrafficIp) return;
    try {
      const res = await fetch('/api/clear-traffic-data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: currentTrafficIp })
      });
      const data = await res.json();
      if (data.success) {
        loadTrafficData(currentTrafficIp);
      } else {
        alert("Error: " + data.error);
      }
    } catch(e) {
      alert("Error: " + e.message);
    }
  });

  // Auto-refresh traffic data every 5 seconds when viewing
  setInterval(() => {
    if (currentTrafficIp && document.getElementById('traffic-data').style.display !== 'none') {
      loadTrafficData(currentTrafficIp);
    }
  }, 5000);

  useLocalBtn.click();
})();
