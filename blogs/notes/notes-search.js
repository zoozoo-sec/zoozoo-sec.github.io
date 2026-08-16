(function () {
  function init() {
    var input = document.getElementById("notes-search-input");
    var results = document.getElementById("notes-search-results");
    var index = window.NOTES_SEARCH_INDEX;
    if (!input || !results || !index) return;

    var active = -1;   // currently highlighted result, -1 = none
    var shown = [];    // entries currently rendered, in order

    function escapeHtml(s) {
      return s.replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }

    function highlight(text, query) {
      var idx = text.toLowerCase().indexOf(query);
      if (idx === -1) return escapeHtml(text);
      return (
        escapeHtml(text.slice(0, idx)) +
        "<mark>" + escapeHtml(text.slice(idx, idx + query.length)) + "</mark>" +
        escapeHtml(text.slice(idx + query.length))
      );
    }

    // Snippet of body text around the match, so a body-only hit shows WHY
    // it matched (e.g. "...reclaims into a freed kmalloc-1024 slot...").
    function highlightSnippet(text, query) {
      var idx = text.toLowerCase().indexOf(query);
      if (idx === -1) return "";
      // Kept short and on its own line (see CSS) so the highlighted match
      // is guaranteed to still be inside the visible width, not truncated
      // off the end by a long "breadcrumb + snippet" single line.
      var start = Math.max(0, idx - 18);
      var end = Math.min(text.length, idx + query.length + 18);
      var snippet = (start > 0 ? "…" : "") + text.slice(start, end) + (end < text.length ? "…" : "");
      return highlight(snippet, query);
    }

    function classify(e, q) {
      var titleHit = e.title.toLowerCase().indexOf(q) !== -1;
      var breadHit = !titleHit && e.breadcrumb.toLowerCase().indexOf(q) !== -1;
      var bodyHit = !titleHit && !breadHit && !!e.text && e.text.toLowerCase().indexOf(q) !== -1;
      return { titleHit: titleHit, breadHit: breadHit, bodyHit: bodyHit };
    }

    function render(query) {
      var q = query.trim().toLowerCase();
      if (!q) {
        results.hidden = true;
        results.innerHTML = "";
        shown = [];
        active = -1;
        return;
      }

      // Rank title hits above breadcrumb hits above body-only hits.
      var titleHits = [], breadHits = [], bodyHits = [];
      index.forEach(function (e) {
        var c = classify(e, q);
        if (c.titleHit) titleHits.push(e);
        else if (c.breadHit) breadHits.push(e);
        else if (c.bodyHit) bodyHits.push(e);
      });
      var matches = titleHits.concat(breadHits).concat(bodyHits).slice(0, 8);

      shown = matches;
      active = matches.length ? 0 : -1;

      if (!matches.length) {
        results.innerHTML = '<div class="notes-search-empty">Oops, no notes match &ldquo;' + escapeHtml(query.trim()) + '&rdquo;</div>';
        results.hidden = false;
        return;
      }

      results.innerHTML = matches.map(function (e, i) {
        var c = classify(e, q);
        var titleHtml = c.titleHit ? highlight(e.title, q) : escapeHtml(e.title);
        var catHtml = c.breadHit ? highlight(e.breadcrumb, q) : escapeHtml(e.breadcrumb);
        var snippetHtml = c.bodyHit ? highlightSnippet(e.text, q) : "";
        return (
          '<a class="notes-search-result' + (i === 0 ? " is-active" : "") + '" href="' + e.href + '" data-idx="' + i + '">' +
            '<span class="notes-search-result-title">' + titleHtml + '</span>' +
            '<span class="notes-search-result-cat">' + catHtml + '</span>' +
            (snippetHtml ? '<span class="notes-search-result-snippet">' + snippetHtml + '</span>' : '') +
          '</a>'
        );
      }).join("");
      results.hidden = false;
    }

    function setActive(i) {
      var rows = results.querySelectorAll(".notes-search-result");
      if (!rows.length) return;
      active = (i + rows.length) % rows.length;
      rows.forEach(function (r, idx) { r.classList.toggle("is-active", idx === active); });
      rows[active].scrollIntoView({ block: "nearest" });
    }

    input.addEventListener("input", function () { render(input.value); });

    input.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        input.value = "";
        render("");
        input.blur();
        return;
      }
      if (e.key === "ArrowDown" && !results.hidden) {
        e.preventDefault();
        setActive(active + 1);
        return;
      }
      if (e.key === "ArrowUp" && !results.hidden) {
        e.preventDefault();
        setActive(active - 1);
        return;
      }
      if (e.key === "Enter") {
        if (active >= 0 && shown[active]) {
          e.preventDefault();
          window.location.href = shown[active].href;
        }
      }
    });

    // Hide on outside click/tap only — NOT on blur. Blur fires the instant
    // you mousedown a result (focus leaves the input), and hiding the
    // dropdown right then can cancel the in-flight click before the browser
    // commits to the navigation. This mirrors notes-nav.js's own pattern.
    document.addEventListener("mousedown", function (e) {
      if (!input.contains(e.target) && !results.contains(e.target)) {
        results.hidden = true;
      }
    });
    input.addEventListener("focus", function () {
      if (input.value.trim() && shown.length) results.hidden = false;
    });

    // "/" focuses search from anywhere on the page, like most doc sites.
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.target === input) return;
      var tag = (e.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || e.target.isContentEditable) return;
      e.preventDefault();
      input.focus();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
