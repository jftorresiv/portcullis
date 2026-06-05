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
    .session { padding: 0.625rem; border-radius: 4px; margin-bottom: 0.5rem; border: 1px solid #21262d; font-size: 0.85rem; }
    .session:last-child { margin-bottom: 0; }
    .session-id { font-family: monospace; font-weight: 600; }
    .session-meta { color: #6e7681; font-size: 0.75rem; margin-top: 0.25rem; }
    .empty { color: #6e7681; font-size: 0.85rem; font-style: italic; }
    .placeholder { color: #6e7681; font-size: 0.85rem; margin: 0; }
  </style>
</head>
<body>
  <h1>Portcullis</h1>
  <p class="tagline">Local security proxy for AI agents</p>

  <section>
    <h2>Status</h2>
    <div id="health"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Sessions</h2>
    <div id="sessions"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Timeline</h2>
    <p class="placeholder">Timeline view coming in issue #7.</p>
  </section>

  <script>
    async function load() {
      try {
        const h = await (await fetch('/api/health')).json();
        document.getElementById('health').innerHTML =
          '<span class="badge"><span class="dot"></span>v' + h.version + '</span>' +
          '&nbsp;&nbsp;<span style="font-size:0.8rem;color:#6e7681">uptime ' + h.uptime_seconds + 's</span>';
      } catch {
        document.getElementById('health').innerHTML = '<span class="empty">Could not reach API</span>';
      }

      try {
        const sessions = await (await fetch('/api/sessions')).json();
        const el = document.getElementById('sessions');
        if (!sessions.length) {
          el.innerHTML = '<span class="empty">No sessions yet. Start a proxy to see activity here.</span>';
          return;
        }
        el.innerHTML = sessions.map(function(s) {
          return '<div class="session">' +
            '<span class="session-id">' + s.session_id.slice(0, 8) + '…</span>' +
            '&nbsp;&nbsp;' + s.servers.join(', ') +
            '<div class="session-meta">' + s.event_count + ' event' + (s.event_count !== 1 ? 's' : '') +
            ' \xb7 last active ' + new Date(s.last_seen).toLocaleString() + '</div>' +
            '</div>';
        }).join('');
      } catch {
        document.getElementById('sessions').innerHTML = '<span class="empty">Failed to load sessions</span>';
      }
    }

    load();
  </script>
</body>
</html>`;
