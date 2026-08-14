(function () {
  function init() {
    var nav = document.getElementById("section-nav");
    if (!nav) return;

    var toggle = nav.querySelector(".section-nav-toggle");
    var links = Array.prototype.slice.call(nav.querySelectorAll(".section-nav-panel a"));
    var targets = links.map(function (a) {
      return document.getElementById(a.getAttribute("href").slice(1));
    });

    function openPanel() {
      nav.classList.add("is-open");
      toggle.setAttribute("aria-expanded", "true");
    }

    function closePanel() {
      nav.classList.remove("is-open");
      toggle.setAttribute("aria-expanded", "false");
    }

    toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      nav.classList.contains("is-open") ? closePanel() : openPanel();
    });

    var closeTimer = null;
    var canHover = window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    if (canHover) {
      nav.addEventListener("mouseenter", function () {
        clearTimeout(closeTimer);
        openPanel();
      });
      nav.addEventListener("mouseleave", function () {
        clearTimeout(closeTimer);
        closeTimer = setTimeout(closePanel, 200);
      });
    }

    links.forEach(function (a, i) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        var target = targets[i];
        if (target) {
          target.scrollIntoView({ behavior: "smooth", block: "start" });
          history.replaceState(null, "", a.getAttribute("href"));
        }
        closePanel();
      });
    });

    document.addEventListener("click", function (e) {
      if (!nav.contains(e.target)) closePanel();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closePanel();
    });

    function updateActive() {
      var scrollPos = window.scrollY + 140;
      var activeIndex = 0;
      targets.forEach(function (t, i) {
        if (t && t.offsetTop <= scrollPos) activeIndex = i;
      });
      links.forEach(function (a, i) {
        a.classList.toggle("is-active", i === activeIndex);
      });
    }

    window.addEventListener("scroll", updateActive, { passive: true });
    updateActive();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
