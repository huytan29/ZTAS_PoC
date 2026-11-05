const form = document.querySelector("#admin-login-form");
const message = document.querySelector("#login-message");
const submit = form.querySelector("button[type=submit]");
const next = new URLSearchParams(location.search).get("next");
const target = next === "/logs" ? "/logs" : "/dashboard";

form.addEventListener("submit", async event => {
  event.preventDefault();
  message.textContent = "Đang xác thực…";
  submit.disabled = true;

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.elements.username.value.trim(),
        password: form.elements.password.value
      })
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) throw new Error(data.error || "Không thể đăng nhập");
    if (data.subject?.role !== "admin") {
      throw new Error("Tài khoản này không có quyền quản trị");
    }

    sessionStorage.setItem("ztas_admin_token", data.access_token);
    location.assign(target);
  } catch (error) {
    message.textContent = error.message === "INVALID_CREDENTIALS"
      ? "Tên đăng nhập hoặc mật khẩu không đúng."
      : error.message;
  } finally {
    submit.disabled = false;
  }
});
