const form = document.querySelector("#setup-form");
const message = document.querySelector("#setup-message");
const submit = document.querySelector("#setup-submit");

async function checkSetupStatus() {
  try {
    const response = await fetch("/api/setup/status", { cache: "no-store" });
    const data = await response.json();

    if (!data.admin_password_setup_required) {
      message.textContent = "Mật khẩu admin đã được thiết lập. Hãy quay lại Dashboard để đăng nhập.";
      message.classList.add("success");
      submit.disabled = true;
    }
  } catch {
    message.textContent = "Không kết nối được với ZTAS.";
  }
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  const password = form.elements.password.value;
  const confirmation = form.elements.confirmation.value;

  if (password !== confirmation) {
    message.textContent = "Xác nhận mật khẩu không khớp.";
    return;
  }

  submit.disabled = true;
  message.classList.remove("success");
  message.textContent = "Đang thiết lập mật khẩu…";

  try {
    const response = await fetch("/api/setup/admin-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password, confirmation })
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.message || data.error || "Thiết lập không thành công");
    }

    form.reset();
    message.textContent = "Đã thiết lập mật khẩu admin. Bạn có thể quay lại Dashboard để đăng nhập.";
    message.classList.add("success");
  } catch (error) {
    message.textContent = error.message;
    submit.disabled = false;
  }
});

checkSetupStatus();
