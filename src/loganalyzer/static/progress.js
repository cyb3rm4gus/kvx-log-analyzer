/* Live progress for a running batch over SSE; reload when it ends (txnscanner pattern —
 * external file because the CSP is `script-src 'self'`). */
(function () {
  "use strict";
  var log = document.getElementById("log");
  if (!log) { return; }
  var batchId = log.getAttribute("data-batch-id");
  if (!batchId) { return; }
  if (!window.EventSource) { setTimeout(function () { location.reload(); }, 5000); return; }
  var source = new EventSource("/batches/" + encodeURIComponent(batchId) + "/events");
  source.onmessage = function (event) {
    var payload;
    try { payload = JSON.parse(event.data); } catch (err) { return; }
    if (!payload.message) { return; }
    var line = document.createElement("div");
    line.textContent = payload.message;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  };
  source.addEventListener("end", function () { source.close(); location.reload(); });
  source.onerror = function () { source.close(); setTimeout(function () { location.reload(); }, 3000); };
})();
