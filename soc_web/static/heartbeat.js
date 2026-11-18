/* Heartbeat monitor. Reads only this site's /heartbeat.json, and puts every value in with textContent, never as HTML
   (host names come from Splunk). The only thing remembered here, for this tab, is whether the panel is open and
   whether it is the bigger size, so changing page does not close it. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var root = $("hb"), toggle = $("hb-toggle"), panel = $("hb-panel");
  if (!root || !toggle || !panel) { return; }

  var els = { label: $("hb-label"), summary: $("hb-summary"), hosts: $("hb-hosts"), size: $("hb-size"), close: $("hb-close") };
  var UI_KEY = "soc-heartbeat-ui", POLL_MS = 15000;
  var ui = { open: false, big: false };
  var timer = null;

  try {
    var saved = JSON.parse(sessionStorage.getItem(UI_KEY) || "null");
    if (saved) { ui.open = saved.open === true; ui.big = saved.big === true; }
  } catch (e) { /* storage may be blocked; the panel then starts closed and small on each page */ }

  function saveUi() {
    try { sessionStorage.setItem(UI_KEY, JSON.stringify(ui)); } catch (e) { /* see above */ }
  }

  function ago(seconds) {
    var m = Math.floor(seconds / 60);
    if (m < 1) { return "just now"; }
    if (m < 60) { return m + " min ago"; }
    var h = Math.floor(m / 60);
    return h + " h " + (m % 60) + " min ago";
  }

  function setText(el, text) { if (el.textContent !== text) { el.textContent = text; } }

  var WORD = { ok: "on time", late: "late", silent: "silent" };

  function summary(data) {
    var worst = data.hosts[0];
    switch (data.state) {
      case "ok": return "All heartbeats on time (" + data.hosts.length + " host" + (data.hosts.length === 1 ? "" : "s") + ").";
      case "late": return worst.host + " is late: last heartbeat " + ago(worst.age) + ". The alert fires after " + (data.silent / 60) + " minutes.";
      case "silent": return worst.host + " has been silent for " + Math.floor(worst.age / 60) + " minutes. Filebeat, Logstash, Splunk or the host may have stopped.";
      case "none": return "No heartbeat in the last six hours. Install the cron file from infra/heartbeat on the host.";
      case "off": return "Splunk is not configured, so there is nothing to watch.";
      default: return "Waiting for Splunk. The state is unknown, which is not the same as silent.";
    }
  }

  function pill(data) {
    var worst = data.hosts[0];
    if (worst && (data.state === "ok" || data.state === "late" || data.state === "silent")) {
      return worst.host + " \u00b7 " + (worst.age < 60 ? "now" : Math.floor(worst.age / 60) + " min");
    }
    return data.state === "none" ? "No heartbeat" : "Heartbeat ?";
  }

  function hostRow(h) {
    var li = document.createElement("li");
    li.className = "hb-host hb-" + h.state;
    var top = document.createElement("div");
    top.className = "hb-host-top";
    var name = document.createElement("b");
    name.textContent = h.host;
    var info = document.createElement("span");
    info.textContent = WORD[h.state] + ", last heartbeat " + ago(h.age);
    top.appendChild(name);
    top.appendChild(info);
    var strip = document.createElement("div");
    strip.className = "hb-ticks";
    strip.setAttribute("aria-hidden", "true");
    var seen = 0, closed = 0;
    h.ticks.forEach(function (t) {
      var tick = document.createElement("i");
      tick.className = "t" + t;
      strip.appendChild(tick);
      if (t === 1) { seen += 1; }
      if (t !== 2) { closed += 1; }
    });
    var caption = document.createElement("p");
    caption.className = "muted hb-caption";
    caption.textContent = seen + " of " + closed + " five-minute slots had a heartbeat";
    li.appendChild(top);
    li.appendChild(strip);
    li.appendChild(caption);
    return li;
  }

  function render(data) {
    root.dataset.state = data.state;
    setText(els.label, pill(data));
    setText(els.summary, summary(data));
    if (!panel.hidden) {
      els.hosts.textContent = "";
      data.hosts.forEach(function (h) { els.hosts.appendChild(hostRow(h)); });
    }
  }

  var last = { state: "unknown", hosts: [], silent: 900 };

  function refresh() {
    if (document.hidden) { return; }
    fetch("/heartbeat.json", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (res) {
        if (res.status === 401 || res.status === 403 || res.redirected) { stop(); root.hidden = true; return null; }
        if (!res.ok) { throw new Error("status " + res.status); }
        return res.json();
      })
      .then(function (data) { if (data) { last = data; render(data); } })
      .catch(function () { last = { state: "unknown", hosts: [], silent: 900 }; render(last); });
  }

  function stop() { if (timer) { clearInterval(timer); timer = null; } }
  function start() { stop(); timer = setInterval(refresh, POLL_MS); }

  function apply() {
    panel.hidden = !ui.open;
    toggle.setAttribute("aria-expanded", ui.open ? "true" : "false");
    root.classList.toggle("hb-big", ui.big);
    els.size.textContent = ui.big ? "Smaller" : "Bigger";
    els.size.setAttribute("aria-pressed", ui.big ? "true" : "false");
    render(last);
    saveUi();
  }

  toggle.addEventListener("click", function () { ui.open = !ui.open; apply(); if (ui.open) { refresh(); } });
  els.close.addEventListener("click", function () { ui.open = false; apply(); toggle.focus(); });
  els.size.addEventListener("click", function () { ui.big = !ui.big; apply(); });
  root.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && ui.open) { ui.open = false; apply(); toggle.focus(); }
  });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) { refresh(); } });

  apply();
  refresh();
  start();
})();
