const form = document.querySelector("#admin-login-form");
const message = document.querySelector("#login-message");
const submit = form.querySelector("button[type=submit]");
const next = new URLSearchParams(location.search).get("next");
const requestedTarget = ["/dashboard", "/logs", "/accounts", "/documents"].includes(next)
  ? next : "";

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
    sessionStorage.setItem("ztas_session_token", data.access_token);
    const target = data.subject?.role === "admin"
      ? (requestedTarget || "/dashboard")
      : "/documents";
    location.assign(target);
  } catch (error) {
    message.textContent = error.message === "INVALID_CREDENTIALS"
      ? "Tên đăng nhập hoặc mật khẩu không đúng."
      : error.message === "DEVICE_BROWSER_PROOF_NOT_VERIFIED"
        ? "Tài khoản này chưa được cấp phát cho trình duyệt/thiết bị hiện tại. Hãy mở trang Kết nối thiết bị để gửi yêu cầu cho quản trị viên."
        : error.message;
  } finally {
    submit.disabled = false;
  }
});
