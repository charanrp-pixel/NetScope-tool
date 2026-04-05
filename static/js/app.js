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

  useLocalBtn.click();
})();
