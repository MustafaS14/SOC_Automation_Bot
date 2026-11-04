/* Chat widget. Talks only to this site's /chat/* routes. All text goes in with textContent, never as HTML, and nothing
   about a conversation is kept in the browser: it lives on the server. The page itself is never read; the server is
   told only the address of the page (path and query) and builds the page context itself. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var fab = $("chat-open"), panel = $("chat-panel");
  if (!fab || !panel) { return; }

  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  var els = {
    title: $("chat-title"), list: $("chat-list"), empty: $("chat-empty"), log: $("chat-log"), error: $("chat-error"),
    use: $("chat-use-page"), chip: $("chat-chip"), form: $("chat-form"), input: $("chat-input"), send: $("chat-send"),
    archivedToggle: $("chat-archived-toggle")
  };
  var state = { conversation: null, archived: false, busy: false };

  function api(method, url, body) {
    var opts = { method: method, headers: { "Accept": "application/json" }, credentials: "same-origin" };
    if (method !== "GET") {
      opts.headers["Content-Type"] = "application/json";
      opts.headers["X-CSRF-Token"] = csrf;
      opts.body = JSON.stringify(body || {});
    }
    return fetch(url, opts).then(function (resp) {
      var type = resp.headers.get("Content-Type") || "";
      if (resp.redirected || type.indexOf("application/json") === -1) {
        throw new Error(resp.status === 400 ? "The page expired. Reload it and try again." : "Your session ended. Sign in again.");
      }
      return resp.json().then(function (data) {
        if (!resp.ok) { throw new Error(data.error || "Something went wrong."); }
        return data;
      });
    });
  }

  function show(message) {
    els.error.textContent = message || "";
    els.error.hidden = !message;
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function bubble(role, text, extra) {
    var wrap = el("div", "msg " + role + (extra && extra.refusal ? " refused" : ""));
    wrap.appendChild(el("div", "who", role === "user" ? "You" : "Assistant"));
    if (extra && extra.page) { wrap.appendChild(el("div", "attached", "page: " + extra.page)); }
    wrap.appendChild(el("div", "text", text));
    if (extra && extra.plain) {
      var plain = el("div", "plain-words");
      plain.appendChild(el("strong", "", "In plain words: "));
      plain.appendChild(document.createTextNode(extra.plain));
      wrap.appendChild(plain);
    }
    els.log.appendChild(wrap);
    els.log.scrollTop = els.log.scrollHeight;
  }

  function currentPath() { return location.pathname + location.search; }

  function refreshChip() {
    api("GET", "/chat/context?path=" + encodeURIComponent(currentPath())).then(function (data) {
      els.chip.textContent = data.label ? "using: " + data.label : "no page information for this page";
      els.use.disabled = !data.label;
      if (!data.label) { els.use.checked = false; }
    }).catch(function () { els.chip.textContent = "no page information"; });
  }

  function renderList(conversations) {
    els.list.textContent = "";
    els.empty.hidden = conversations.length > 0;
    conversations.forEach(function (c) {
      var li = el("li", c.id === state.conversation ? "on" : "");
      var open = el("button", "chat-item", c.title);
      open.type = "button";
      open.addEventListener("click", function () { openConversation(c.id); });
      var rename = el("button", "chat-mini", "Rename");
      rename.type = "button";
      rename.setAttribute("aria-label", "Rename " + c.title);
      rename.addEventListener("click", function () { startRename(li, c); });
      var archive = el("button", "chat-mini", c.archived ? "Restore" : "Archive");
      archive.type = "button";
      archive.setAttribute("aria-label", (c.archived ? "Restore " : "Archive ") + c.title);
      archive.addEventListener("click", function () {
        api("POST", "/chat/conversations/" + c.id + "/archive", { archived: !c.archived }).then(function () {
          if (state.conversation === c.id && !c.archived) { newChat(); }
          loadList();
        }).catch(function (e) { show(e.message); });
      });
      li.appendChild(open); li.appendChild(rename); li.appendChild(archive);
      els.list.appendChild(li);
    });
  }

  function startRename(li, c) {
    li.textContent = "";
    var input = el("input", "chat-rename");
    input.type = "text"; input.maxLength = 80; input.value = c.title;
    input.setAttribute("aria-label", "New name for " + c.title);
    li.appendChild(input);
    input.focus(); input.select();
    function done(save) {
      if (!save || !input.value.trim()) { loadList(); return; }
      api("POST", "/chat/conversations/" + c.id + "/rename", { title: input.value }).then(function (data) {
        if (state.conversation === c.id) { els.title.textContent = data.conversation.title; }
        loadList();
      }).catch(function (e) { show(e.message); loadList(); });
    }
    input.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") { ev.preventDefault(); done(true); }
      if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); done(false); }
    });
  }

  function loadList() {
    return api("GET", "/chat/conversations" + (state.archived ? "?archived=1" : "")).then(function (data) {
      renderList(data.conversations);
    }).catch(function (e) { show(e.message); });
  }

  function openConversation(id) {
    show("");
    return api("GET", "/chat/conversations/" + id).then(function (data) {
      state.conversation = id;
      els.title.textContent = data.conversation.title;
      els.log.textContent = "";
      data.messages.forEach(function (m) {
        bubble(m.role, m.text, { plain: m.plain, page: m.page, refusal: m.refusal });
      });
      loadList();
    }).catch(function (e) { show(e.message); });
  }

  function newChat() {
    state.conversation = null;
    els.title.textContent = "New conversation";
    els.log.textContent = "";
    show("");
    loadList();
    els.input.focus();
  }

  function openPanel() {
    panel.hidden = false;
    fab.setAttribute("aria-expanded", "true");
    refreshChip();
    loadList();
    els.input.focus();
  }

  function closePanel() {
    panel.hidden = true;
    fab.setAttribute("aria-expanded", "false");
    fab.focus();
  }

  fab.addEventListener("click", function (ev) {
    ev.preventDefault();  // without JavaScript the button is a link to the Ask page
    if (panel.hidden) { openPanel(); } else { closePanel(); }
  });
  $("chat-close").addEventListener("click", closePanel);
  $("chat-new").addEventListener("click", newChat);
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && !panel.hidden) { ev.preventDefault(); closePanel(); }
  });
  els.archivedToggle.addEventListener("click", function () {
    state.archived = !state.archived;
    els.archivedToggle.textContent = state.archived ? "Show current" : "Show archived";
    loadList();
  });
  els.input.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); els.form.requestSubmit(); }
  });

  els.form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var question = els.input.value.trim();
    if (!question || state.busy) { return; }
    state.busy = true; els.send.disabled = true; show("");
    var attach = els.use.checked && !els.use.disabled;
    bubble("user", question, { page: attach ? els.chip.textContent.replace(/^using: /, "") : null });
    els.input.value = "";
    api("POST", "/chat/ask", {
      question: question, conversation: state.conversation, path: currentPath(), use_page: attach
    }).then(function (data) {
      state.conversation = data.conversation.id;
      els.title.textContent = data.conversation.title;
      bubble("assistant", data.answer.text, { plain: data.answer.plain, refusal: data.answer.refusal });
      loadList();
    }).catch(function (e) {
      show(e.message);
    }).then(function () {
      state.busy = false; els.send.disabled = false; els.input.focus();
    });
  });
}());
