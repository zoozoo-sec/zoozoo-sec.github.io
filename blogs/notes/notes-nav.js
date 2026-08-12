(function () {
  function init() {
    var nav = document.getElementById("notes-nav");
    if (!nav) return;
    var toggle = nav.querySelector(".notes-nav-toggle");

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

    document.addEventListener("click", function (e) {
      if (!nav.contains(e.target)) closePanel();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closePanel();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
