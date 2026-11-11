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

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/service-worker.js").catch(() => undefined);
    });
  }

  const installButton = document.querySelector("#install-app-button");
  let deferredInstallPrompt = null;
  const isIos = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  const isStandalone = window.matchMedia("(display-mode: standalone)").matches ||
    navigator.standalone === true;

  window.addEventListener("beforeinstallprompt", event => {
    event.preventDefault();
    deferredInstallPrompt = event;
    if (installButton && !isStandalone) installButton.hidden = false;
  });

  if (installButton && isIos && !isStandalone) installButton.hidden = false;
  installButton?.addEventListener("click", async () => {
    if (deferredInstallPrompt) {
      deferredInstallPrompt.prompt();
      await deferredInstallPrompt.userChoice;
      deferredInstallPrompt = null;
      installButton.hidden = true;
      return;
    }
    if (isIos) {
      alert("Trong Safari, chọn Chia sẻ → Thêm vào Màn hình chính để cài ứng dụng.");
    }
  });
})();
