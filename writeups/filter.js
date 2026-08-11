document.addEventListener("DOMContentLoaded", function () {
  var buttons = document.querySelectorAll(".category-btn");
  var groups = document.querySelectorAll(".category-group");

  function applyFilter(filter) {
    groups.forEach(function (group) {
      group.hidden = filter !== "all" && group.dataset.category !== filter;
    });
    buttons.forEach(function (btn) {
      btn.classList.toggle("is-active", btn.dataset.filter === filter);
    });
  }

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      applyFilter(btn.dataset.filter);
    });
  });

  document.querySelectorAll(".show-more-btn").forEach(function (btn) {
    var grid = btn.previousElementSibling;
    var extras = grid.querySelectorAll(".writeup-card.is-extra");
    var moreLabel = btn.textContent;
    var expanded = false;

    btn.addEventListener("click", function () {
      expanded = !expanded;
      extras.forEach(function (card) {
        card.classList.toggle("is-extra", !expanded);
      });
      btn.textContent = expanded ? "Show less" : moreLabel;
      if (!expanded) {
        grid.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    });
  });
});
