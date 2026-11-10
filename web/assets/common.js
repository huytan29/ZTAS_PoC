(() => {
  const storageKey = "ztas_theme";
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
})();
