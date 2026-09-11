/* Native <dialog> open/close via data attributes (external file: CSP is script-src 'self'). */
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var open = ev.target.closest("[data-open-dialog]");
    if (open) { var d = document.getElementById(open.getAttribute("data-open-dialog")); if (d && d.showModal) { d.showModal(); var i = d.querySelector("input"); if (i) { i.focus(); i.select(); } } return; }
    var close = ev.target.closest("[data-close-dialog]");
    if (close) { var c = document.getElementById(close.getAttribute("data-close-dialog")); if (c) { c.close(); } }
  });
})();
