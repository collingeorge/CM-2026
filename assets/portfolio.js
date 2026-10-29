"use strict";
document.documentElement.classList.add("js-enabled");
const menuButton = document.querySelector(".menu-toggle");
const siteNav = document.getElementById("site-nav");
if (menuButton && siteNav) {
  menuButton.hidden = false;
  const closeMenu = () => { menuButton.setAttribute("aria-expanded", "false"); siteNav.classList.remove("is-open"); };
  menuButton.addEventListener("click", () => {
    const open = menuButton.getAttribute("aria-expanded") !== "true";
    menuButton.setAttribute("aria-expanded", String(open));
    siteNav.classList.toggle("is-open", open);
  });
  siteNav.addEventListener("click", event => { if (event.target.closest("a")) closeMenu(); });
  document.addEventListener("keydown", event => { if (event.key === "Escape" && menuButton.getAttribute("aria-expanded") === "true") { closeMenu(); menuButton.focus(); } });
}
const tools = document.querySelector(".library-tools");
const filters = Array.from(document.querySelectorAll("[data-filter]"));
const projects = Array.from(document.querySelectorAll(".library-row"));
const count = document.querySelector(".result-count");
if (tools && count && filters.length && projects.length) {
  tools.hidden = false;
  filters.forEach(button => button.addEventListener("click", () => {
    const selected = button.dataset.filter;
    let visible = 0;
    projects.forEach(project => {
      const show = selected === "All" || project.dataset.category === selected;
      project.hidden = !show;
      if (show) visible++;
    });
    filters.forEach(filter => filter.setAttribute("aria-pressed", String(filter === button)));
    count.textContent = visible + (visible === 1 ? " project" : " projects");
  }));
}
