/* Timeline hover: a vertical guide on both charts and one tooltip with the numbers for the slot under the pointer.
   The numbers come from the page itself (data-tips on the chart panel); nothing is fetched. All text goes in with
   textContent. The table under the charts has the same numbers for anyone who does not use a pointer. */
(function () {
  "use strict";
  var panel = document.getElementById("tl"), tip = document.getElementById("tl-tip");
  if (!panel || !tip) { return; }
  var tips = [];
  try { tips = JSON.parse(panel.getAttribute("data-tips") || "[]"); } catch (e) { return; }
  var svgs = Array.prototype.slice.call(panel.querySelectorAll(".tl-svg"));

  function add(parent, tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) { el.className = cls; }
    if (text !== undefined) { el.textContent = text; }
    parent.appendChild(el);
    return el;
  }

  function section(title, total, rows) {
    var box = add(tip, "div", "tl-tip-sec");
    add(box, "div", "tl-tip-h", title + (rows.length ? " \u00b7 " + total : ""));
    if (!rows.length) { add(box, "div", "tl-tip-none", "nothing in this slot"); return; }
    rows.forEach(function (r) {
      var line = add(box, "div", "tl-tip-row");
      add(line, "i", "key sw-" + String(r[2]).replace(/[^a-z0-9]/g, ""));
      add(line, "b", "", String(r[1]));
      add(line, "span", "", String(r[0]));
    });
  }

  function show(i, x, y) {
    var t = tips[i];
    if (!t) { return; }
    tip.textContent = "";
    add(tip, "div", "tl-tip-when", t.when);
    if (panel.querySelector(".tl-svg[aria-labelledby=tl-a-t]")) { section("Alerts", t.alert_total, t.alerts); }
    if (panel.querySelector(".tl-svg[aria-labelledby=tl-b-t]")) { section("Log activity", t.activity_total, t.activity); }
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    var left = x + 16, top = y + 16;
    if (left + w > window.innerWidth - 8) { left = x - w - 16; }
    if (top + h > window.innerHeight - 8) { top = Math.max(8, y - h - 16); }
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = top + "px";
  }

  function guide(centre) {
    svgs.forEach(function (svg) {
      var line = svg.querySelector(".tl-cross");
      if (!line) { return; }
      if (centre === null) { line.setAttribute("hidden", ""); svg.classList.remove("hov"); return; }
      line.setAttribute("x1", centre); line.setAttribute("x2", centre);
      line.removeAttribute("hidden");
      svg.classList.add("hov");
    });
  }

  function mark(i) {
    svgs.forEach(function (svg) {
      Array.prototype.forEach.call(svg.querySelectorAll(".tl-col"), function (g) {
        g.classList.toggle("on", i !== null && g.getAttribute("data-i") === String(i));
      });
    });
  }

  panel.addEventListener("pointermove", function (e) {
    var hit = e.target.closest ? e.target.closest(".tl-hit") : null;
    if (!hit) { return; }
    var i = hit.getAttribute("data-i");
    var centre = parseFloat(hit.getAttribute("x")) + parseFloat(hit.getAttribute("width")) / 2;
    guide(centre);
    mark(i);
    show(Number(i), e.clientX, e.clientY);
  });
  panel.addEventListener("pointerleave", function () { tip.hidden = true; guide(null); mark(null); });
})();
