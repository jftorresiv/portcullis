export const dashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Portcullis</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f1117; color: #c9d1d9; margin: 0; padding: 2rem; }
    h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: 0.25rem; }
    .tagline { color: #6e7681; font-size: 0.85rem; margin-bottom: 2rem; }
    section { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }
    h2 { font-size: 0.8rem; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
    .badge { display: inline-flex; align-items: center; gap: 0.4rem; background: #0d1117; border: 1px solid #21262d; border-radius: 2rem; padding: 0.25rem 0.75rem; font-size: 0.8rem; font-family: monospace; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; display: inline-block; }
    .dot.red { background: #f85149; }
    .session { padding: 0.625rem; border-radius: 4px; margin-bottom: 0.5rem; border: 1px solid #21262d; font-size: 0.85rem; }
    .session:last-child { margin-bottom: 0; }
    .session-id { font-family: monospace; font-weight: 600; }
    .session-meta { color: #6e7681; font-size: 0.75rem; margin-top: 0.25rem; }
    .session-flags { display: inline-flex; gap: 0.375rem; margin-left: 0.5rem; }
    .flag-tag {
      font-size: 0.65rem; font-family: monospace; padding: 0.1rem 0.4rem;
      border-radius: 3px; border: 1px solid; text-transform: uppercase;
    }
    .flag-trifecta { color: #f85149; border-color: #f8514940; }
    .flag-tainted { color: #d29922; border-color: #d2992240; }
    .empty { color: #6e7681; font-size: 0.85rem; font-style: italic; }

    .alert-row {
      padding: 0.5rem 0.625rem; border-radius: 4px; margin-bottom: 0.375rem;
      border: 1px solid #21262d; font-size: 0.8rem;
    }
    .alert-row:last-child { margin-bottom: 0; }
    .alert-tool { font-family: monospace; font-weight: 600; }
    .alert-meta { color: #6e7681; font-size: 0.75rem; margin-top: 0.2rem; }
    .alert-severity {
      font-size: 0.65rem; font-family: monospace; padding: 0.1rem 0.4rem;
      border-radius: 3px; border: 1px solid; text-transform: uppercase; margin-left: 0.4rem;
    }

    .ks-row { display: flex; align-items: center; gap: 1rem; }
    .ks-status { font-size: 0.85rem; }
    .ks-button {
      background: #21262d; color: #c9d1d9; border: 1px solid #f85149;
      border-radius: 4px; padding: 0.4rem 0.9rem; font-size: 0.8rem;
      font-weight: 600; cursor: pointer;
    }
    .ks-button:hover { background: #f8514920; }
    .ks-button:disabled { opacity: 0.5; cursor: not-allowed; }

    .tl-filters { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
    .tl-filters input, .tl-filters select {
      background: #0d1117; border: 1px solid #21262d; color: #c9d1d9;
      border-radius: 4px; padding: 0.35rem 0.6rem; font-size: 0.8rem; outline: none;
    }
    .tl-filters input:focus, .tl-filters select:focus { border-color: #58a6ff; }
    .tl-filters input::placeholder { color: #6e7681; }
    .tl-filters select option { background: #161b22; }
    .tl-row { border: 1px solid #21262d; border-radius: 4px; margin-bottom: 0.375rem; overflow: hidden; }
    .tl-row:last-child { margin-bottom: 0; }
    .tl-header {
      display: grid;
      grid-template-columns: 5.5rem 5.25rem 1.5rem 1fr 1fr 5rem;
      gap: 0.5rem; align-items: center;
      padding: 0.5rem 0.75rem; cursor: pointer;
      font-size: 0.8rem; user-select: none;
    }
    .tl-header:hover { background: #1c2128; }
    .tl-row.expanded > .tl-header { background: #1c2128; border-bottom: 1px solid #21262d; }
    .tl-time { color: #6e7681; font-family: monospace; white-space: nowrap; }
    .tl-session { font-family: monospace; color: #8b949e; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tl-dir { color: #6e7681; text-align: center; }
    .tl-server { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tl-method { font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tl-decision {
      font-size: 0.7rem; font-family: monospace; text-align: center;
      border: 1px solid; border-radius: 3px; padding: 0.15rem 0.4rem; white-space: nowrap;
    }
    .tl-detail { display: none; padding: 0.75rem; background: #0d1117; }
    .tl-row.expanded > .tl-detail { display: block; }
    .tl-caps { display: flex; gap: 0.375rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
    .cap-tag {
      font-size: 0.7rem; font-family: monospace; padding: 0.15rem 0.4rem;
      border-radius: 3px; background: #161b22; border: 1px solid #21262d; color: #8b949e;
    }
    .tl-payload {
      margin: 0; font-size: 0.75rem; color: #c9d1d9; white-space: pre-wrap;
      word-break: break-all; max-height: 20rem; overflow-y: auto;
      background: #0d1117; line-height: 1.5;
    }
  </style>
</head>
<body>
  <h1>Portcullis</h1>
  <p class="tagline">Local security proxy for AI agents</p>

  <section>
    <h2>Status</h2>
    <div id="health"><span class="empty">Loading&#8230;</span></div>
  </section>

  <section>
    <h2>Kill Switch</h2>
    <div class="ks-row">
      <span id="ks-status" class="ks-status"><span class="empty">Loading&#8230;</span></span>
      <button id="ks-button" class="ks-button">Activate kill switch</button>
    </div>
  </section>

  <section>
    <h2>Sessions</h2>
    <div id="sessions"><span class="empty">Loading&#8230;</span></div>
  </section>

  <section>
    <h2>Injection Alerts</h2>
    <div id="injection-alerts"><span class="empty">Loading&#8230;</span></div>
  </section>

  <section>
    <h2>Timeline</h2>
    <div class="tl-filters">
      <input id="filter-server" type="text" placeholder="Filter by server&#8230;" style="flex:1;min-width:8rem">
      <input id="filter-method" type="text" placeholder="Filter by tool / method&#8230;" style="flex:1;min-width:10rem">
      <select id="filter-decision">
        <option value="">All decisions</option>
        <option value="allowed">Allowed</option>
        <option value="blocked">Blocked</option>
        <option value="warned">Warned</option>
        <option value="confirmed">Confirmed</option>
      </select>
    </div>
    <div id="timeline"><span class="empty">Loading&#8230;</span></div>
  </section>

  <script>
    // ---- health + sessions ----
    async function load() {
      try {
        var h = await (await fetch('/api/health')).json();
        document.getElementById('health').innerHTML =
          '<span class="badge"><span class="dot"></span>v' + h.version + '</span>' +
          '&nbsp;&nbsp;<span style="font-size:0.8rem;color:#6e7681">uptime ' + h.uptime_seconds + 's</span>';
      } catch (e) {
        document.getElementById('health').innerHTML = '<span class="empty">Could not reach API</span>';
      }

      try {
        var sessions = await (await fetch('/api/sessions')).json();
        var el = document.getElementById('sessions');
        if (!sessions.length) {
          el.innerHTML = '<span class="empty">No sessions yet. Start a proxy to see activity here.</span>';
        } else {
          el.innerHTML = sessions.map(function(s) {
            var flags = '';
            if (s.trifecta || s.tainted) {
              flags = '<span class="session-flags">' +
                (s.trifecta ? '<span class="flag-tag flag-trifecta">trifecta</span>' : '') +
                (s.tainted ? '<span class="flag-tag flag-tainted">tainted</span>' : '') +
                '</span>';
            }
            return '<div class="session">' +
              '<span class="dot' + (s.trifecta ? ' red' : '') + '"></span>&nbsp;' +
              '<span class="session-id">' + s.session_id.slice(0, 8) + '&#8230;</span>' +
              '&nbsp;&nbsp;' + s.servers.join(', ') + flags +
              '<div class="session-meta">' + s.event_count + ' event' + (s.event_count !== 1 ? 's' : '') +
              ' \xb7 last active ' + new Date(s.last_seen).toLocaleString() + '</div>' +
              '</div>';
          }).join('');
        }
      } catch (e) {
        document.getElementById('sessions').innerHTML = '<span class="empty">Failed to load sessions</span>';
      }
    }

    load();
    setInterval(load, 1000);

    // ---- injection alerts ----
    async function loadInjectionAlerts() {
      try {
        var events = await (await fetch('/api/events?type=injection_scan_alert&limit=25')).json();
        var el = document.getElementById('injection-alerts');
        if (!events.length) {
          el.innerHTML = '<span class="empty">No injection alerts.</span>';
          return;
        }
        events.sort(function(a, b) { return a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0; });
        el.innerHTML = events.map(function(e) {
          var m = e.message || {};
          var sev = m.severity || 'warn';
          var sevColor = sev === 'critical' ? '#f85149' : '#d29922';
          return '<div class="alert-row">' +
            '<span class="alert-tool">' + escHtml(m.toolName || '') + '</span>' +
            '<span class="alert-severity" style="color:' + sevColor + ';border-color:' + sevColor + '40">' + escHtml(sev) + '</span>' +
            '<div class="alert-meta">' + escHtml(m.field || '') + ': ' + escHtml(m.pattern || '') +
            ' \xb7 ' + new Date(e.timestamp).toLocaleString() + '</div>' +
            '</div>';
        }).join('');
      } catch (e) {
        document.getElementById('injection-alerts').innerHTML = '<span class="empty">Failed to load injection alerts.</span>';
      }
    }

    loadInjectionAlerts();
    setInterval(loadInjectionAlerts, 1000);

    // ---- kill switch ----
    var ksBusy = false;

    async function loadKillSwitchStatus() {
      try {
        var s = await (await fetch('/api/kill-switch/status')).json();
        var el = document.getElementById('ks-status');
        el.innerHTML = s.frozen
          ? '<span class="dot red"></span>&nbsp;FROZEN'
          : '<span class="dot"></span>&nbsp;running';
        document.getElementById('ks-button').disabled = ksBusy || !!s.frozen;
      } catch (e) {
        document.getElementById('ks-status').innerHTML = '<span class="empty">Could not reach API</span>';
      }
    }

    document.getElementById('ks-button').addEventListener('click', async function() {
      if (ksBusy) return;
      if (!confirm('Activate the kill switch? This immediately freezes all forwarding to the MCP server.')) return;
      ksBusy = true;
      document.getElementById('ks-button').disabled = true;
      try {
        await fetch('/api/kill-switch/activate', { method: 'POST' });
      } catch (e) {
        // status poll will reflect whatever the actual state is
      } finally {
        ksBusy = false;
        loadKillSwitchStatus();
      }
    });

    loadKillSwitchStatus();
    setInterval(loadKillSwitchStatus, 1000);

    // ---- timeline ----
    var tlState = {
      events: [],
      expanded: {},
      lastHash: '',
      filters: { server: '', method: '', decision: '' }
    };

    function escHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function evtKey(e) {
      return e.timestamp + '|' + e.session_id + '|' + e.direction + '|' + e.method;
    }

    function decisionStyle(d) {
      var c = d === 'allowed'   ? '#3fb950'
            : d === 'blocked'   ? '#f85149'
            : d === 'warned'    ? '#d29922'
            : d === 'confirmed' ? '#58a6ff'
            : '#6e7681';
      return 'color:' + c + ';border-color:' + c + '40';
    }

    function fmtTime(ts) {
      return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function applyFilters(events) {
      var f = tlState.filters;
      return events.filter(function(e) {
        if (f.server   && e.server.toLowerCase().indexOf(f.server.toLowerCase())   === -1) return false;
        if (f.method   && e.method.toLowerCase().indexOf(f.method.toLowerCase())   === -1) return false;
        if (f.decision && e.decision !== f.decision) return false;
        return true;
      });
    }

    function renderTimeline() {
      var container = document.getElementById('timeline');
      var filtered = applyFilters(tlState.events);

      if (filtered.length === 0) {
        container.innerHTML = tlState.events.length === 0
          ? '<span class="empty">No events yet. Make a tool call through Portcullis to see it here.</span>'
          : '<span class="empty">No events match the current filters.</span>';
        return;
      }

      var frag = document.createDocumentFragment();
      for (var i = 0; i < filtered.length; i++) {
        var e = filtered[i];
        var key = evtKey(e);
        var isExpanded = !!tlState.expanded[key];

        var row = document.createElement('div');
        row.className = 'tl-row' + (isExpanded ? ' expanded' : '');
        row.dataset.key = key;

        var dir = e.direction === 'client_to_server' ? '&rarr;' : '&larr;';
        var dLabel = e.decision || 'pass';

        var header = document.createElement('div');
        header.className = 'tl-header';
        header.innerHTML =
          '<span class="tl-time">'    + fmtTime(e.timestamp) + '</span>' +
          '<span class="tl-session" title="' + escHtml(e.session_id) + '">' + e.session_id.slice(0, 8) + '&#8230;</span>' +
          '<span class="tl-dir">'     + dir + '</span>' +
          '<span class="tl-server" title="' + escHtml(e.server) + '">'  + escHtml(e.server)  + '</span>' +
          '<span class="tl-method" title="' + escHtml(e.method) + '">'  + escHtml(e.method)  + '</span>' +
          '<span class="tl-decision" style="' + decisionStyle(e.decision) + '">' + escHtml(dLabel) + '</span>';

        var detail = document.createElement('div');
        detail.className = 'tl-detail';

        var capHtml = '';
        if (e.capabilities && e.capabilities.length) {
          capHtml = '<div class="tl-caps">' + e.capabilities.map(function(c) {
            return '<span class="cap-tag">' + escHtml(c) + '</span>';
          }).join('') + '</div>';
        }
        var ruleHtml = e.matchedRule
          ? '<div class="tl-caps"><span class="cap-tag">rule: ' + escHtml(e.matchedRule) + '</span></div>'
          : '';
        detail.innerHTML = capHtml + ruleHtml + '<pre class="tl-payload">' + escHtml(JSON.stringify(e.message, null, 2)) + '</pre>';

        row.appendChild(header);
        row.appendChild(detail);
        frag.appendChild(row);
      }

      container.innerHTML = '';
      container.appendChild(frag);
    }

    // Toggle expand/collapse via event delegation — survives re-renders
    document.getElementById('timeline').addEventListener('click', function(evt) {
      var row = evt.target.closest('.tl-row');
      if (!row) return;
      var key = row.dataset.key;
      if (tlState.expanded[key]) {
        delete tlState.expanded[key];
        row.classList.remove('expanded');
      } else {
        tlState.expanded[key] = true;
        row.classList.add('expanded');
      }
    });

    document.getElementById('filter-server').addEventListener('input', function() {
      tlState.filters.server = this.value;
      renderTimeline();
    });
    document.getElementById('filter-method').addEventListener('input', function() {
      tlState.filters.method = this.value;
      renderTimeline();
    });
    document.getElementById('filter-decision').addEventListener('change', function() {
      tlState.filters.decision = this.value;
      renderTimeline();
    });

    async function fetchTimeline() {
      try {
        var events = await (await fetch('/api/events')).json();
        // Newest first
        events.sort(function(a, b) {
          return a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0;
        });
        var hash = events.length + '|' + (events[0] ? events[0].timestamp : '');
        if (hash === tlState.lastHash) return;
        tlState.lastHash = hash;
        tlState.events = events;
        renderTimeline();
      } catch (e) {
        if (!tlState.events.length) {
          document.getElementById('timeline').innerHTML = '<span class="empty">Could not load events.</span>';
        }
      }
    }

    fetchTimeline();
    setInterval(fetchTimeline, 2000);
  </script>
</body>
</html>`;
