/* Live batch view by polling /status (external file: CSP is script-src 'self').
 * Updates the uuid table, the phase line and the enrichment bar, and the log —
 * so a long enrichment phase no longer leaves the table frozen on "fetching". */
(function () {
  "use strict";
  var root = document.getElementById("batch");
  if (!root) { return; }
  var id = root.getAttribute("data-batch-id");
  var tbody = document.getElementById("uuid-rows");
  var phaseEl = document.getElementById("phase");
  var logEl = document.getElementById("log");
  var flags = function (f) {
    var out = "";
    if (f.ua_downgrade) { out += '<span class="badge bg-red-lt">UA downgrade ' + f.ua_downgrade + '</span> '; }
    if (f.ua_jump) { out += '<span class="badge bg-orange-lt" title="browser major version moved by 2 or more">UA jump \u22652 ' + f.ua_jump + '</span> '; }
    if (f.both) { out += '<span class="badge bg-purple-lt">UA+ASN ' + f.both + '</span> '; }
    if (f.asn) { out += '<span class="badge bg-yellow-lt">ASN ' + f.asn + '</span> '; }
    if (f.ua_other) { out += '<span class="badge bg-azure-lt">UA ' + f.ua_other + '</span>'; }
    return out;
  };
  var esc = function (s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; };

  function draw(d) {
    var badge = d.badge || {};
    if (tbody) {
      tbody.innerHTML = d.uuids.map(function (u) {
        var cls = badge[u.status] || "bg-secondary-lt";
        var pages = u.pages;
        return '<tr><td><a class="font-monospace" href="/accounts/' + esc(u.uuid) + '">' + esc(u.uuid) + '</a></td>' +
          '<td><span class="badge ' + cls + '">' + esc(u.status) + '</span></td>' +
          '<td class="text-end">' + pages + '</td>' +
          '<td class="text-end">' + u.events + '</td>' +
          '<td class="text-end">' + u.ips + '</td>' +
          '<td class="text-nowrap">' + flags(u.flags || {}) + '</td>' +
          '<td class="text-secondary small">' + esc(u.error) + '</td></tr>';
      }).join("");
    }
    if (phaseEl) {
      var txt;
      if (d.phase === "fetching") { txt = "Fetching events from Guardhouse…"; }
      else if (d.phase === "enriching") {
        txt = "Events in. Enriching IP addresses (RDAP + ASN, ~1/sec per registry) — account pages are ready to open now.";
        if (d.enrich) { txt += " " + d.enrich.done + " of " + d.enrich.total + " IPs."; }
      } else if (d.phase === "done") { txt = "Done."; }
      else if (d.phase === "failed") { txt = "Batch failed."; }
      else { txt = d.phase; }
      var cls = badge[d.phase] || "bg-secondary-lt";
      var bar = "";
      if (d.enrich && d.enrich.total) {
        var pct = Math.round(100 * d.enrich.done / d.enrich.total);
        bar = '<div class="progress mt-2" style="height:6px"><div class="progress-bar" style="width:' + pct + '%"></div></div>';
      }
      phaseEl.innerHTML = '<span class="badge ' + cls + ' me-2">' + esc(d.phase) + '</span>' + esc(txt) + bar;
    }
    if (logEl && d.log) {
      logEl.innerHTML = d.log.map(function (m) { return "<div>" + esc(m) + "</div>"; }).join("");
      logEl.scrollTop = logEl.scrollHeight;
    }
  }

  function tick() {
    fetch("/batches/" + encodeURIComponent(id) + "/status", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        draw(d);
        if (d.live) { setTimeout(tick, 2000); }
        else { setTimeout(function () { location.reload(); }, 1500); }
      })
      .catch(function () { setTimeout(tick, 4000); });
  }
  tick();
})();
