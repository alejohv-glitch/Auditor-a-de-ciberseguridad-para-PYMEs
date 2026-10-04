// Minimal progressive enhancement. The app works without JavaScript.
document.addEventListener("click", function (e) {
  var t = e.target.closest("[data-print]");
  if (t) { e.preventDefault(); window.print(); }
  var c = e.target.closest("[data-confirm]");
  if (c && !window.confirm(c.getAttribute("data-confirm"))) { e.preventDefault(); }
});
