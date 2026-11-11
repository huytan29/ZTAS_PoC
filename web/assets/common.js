(() => {
  const storageKey = "ztas_theme";
  const sidebarStorageKey = "ztas_sidebar_open";
  const root = document.documentElement;
  const systemPrefersDark = window.matchMedia("(prefers-color-scheme: dark)");

  function currentTheme() {
    return root.dataset.theme || (systemPrefersDark.matches ? "dark" : "light");
  }

  function updateButtons(theme) {
    document.querySelectorAll("[data-theme-toggle]").forEach(button => {
      const isDark = theme === "dark";
      button.setAttribute("aria-pressed", String(isDark));
      button.setAttribute("title", isDark ? "Chuyển sang giao diện sáng" : "Chuyển sang giao diện tối");
      button.innerHTML = isDark ? "☀ <span>Sáng</span>" : "◐ <span>Tối</span>";
    });
  }

  function applyTheme(theme, persist = false) {
    root.dataset.theme = theme;
    updateButtons(theme);
    if (persist) localStorage.setItem(storageKey, theme);
  }

  applyTheme(localStorage.getItem(storageKey) || currentTheme());
  document.querySelectorAll("[data-theme-toggle]").forEach(button => {
    button.addEventListener("click", () => {
      applyTheme(currentTheme() === "dark" ? "light" : "dark", true);
    });
  });

  function applySidebar(open, persist = false) {
    root.dataset.sidebarOpen = String(open);
    document.querySelectorAll("[data-sidebar-toggle]").forEach(button => {
      button.setAttribute("aria-expanded", String(open));
      button.setAttribute("aria-label", open ? "Ẩn menu" : "Mở menu");
      button.setAttribute("title", open ? "Ẩn menu" : "Mở menu");
      if (button.classList.contains("sidebar-launcher")) {
        button.querySelector("span").textContent = open ? "×" : "☰";
      } else {
        button.textContent = open ? "×" : "☰";
      }
    });
    if (persist) localStorage.setItem(sidebarStorageKey, String(open));
  }

  applySidebar(localStorage.getItem(sidebarStorageKey) === "true");
  document.querySelectorAll("[data-sidebar-toggle]").forEach(button => {
    button.addEventListener("click", () => {
      applySidebar(root.dataset.sidebarOpen !== "true", true);
    });
  });
})();
