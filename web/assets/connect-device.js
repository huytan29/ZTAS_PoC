const form = document.querySelector("#connect-device-form");
const message = document.querySelector("#connect-device-message");
const submit = form.querySelector("button[type=submit]");
let approvalPoll = 0;
let waitingApproval = false;
let retriedWithFreshIdentity = false;

function getDeviceId() {
  const stored = localStorage.getItem("ztas_connect_device_id");
  if (stored) return stored;
  const random = globalThis.crypto?.randomUUID?.().replaceAll("-", "") ??
    `${Date.now()}${Math.random().toString(16).slice(2)}`;
  const value = `web-${random.slice(0, 24).toLowerCase()}`;
  localStorage.setItem("ztas_connect_device_id", value);
  return value;
}

function createFreshDeviceIdentity() {
  localStorage.removeItem("ztas_connect_device_id");
  return getDeviceId();
}

function deviceType() {
  const platform = `${navigator.userAgentData?.platform ?? ""} ${navigator.platform ?? ""} ${navigator.userAgent}`.toLowerCase();
  if (platform.includes("windows")) return "windows";
  if (platform.includes("mac")) return "macos";
  if (platform.includes("linux") || platform.includes("ubuntu")) return "ubuntu";
  return "unknown";
}

function deviceName() {
  const label = navigator.userAgentData?.platform || navigator.platform || "Thiết bị web";
  return `${label} · ${deviceType()}`;
}

async function waitForApproval() {
  window.clearTimeout(approvalPoll);
  try {
    const response = await fetch("/api/reader-context", { cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (response.ok && data.access_token && data.reader_context) {
      sessionStorage.setItem("ztas_document_token", data.access_token);
      sessionStorage.setItem("ztas_document_context", JSON.stringify({
        username: data.subject.username,
        role: data.subject.role,
        ...data.reader_context
      }));
      message.textContent = "Thiết bị đã được phê duyệt. Đang mở Tài liệu…";
      location.assign("/documents");
      return;
    }
    if (response.status === 401) {
      waitingApproval = false;
      submit.disabled = false;
      message.textContent = "Phiên chờ phê duyệt đã hết hạn. Nhập lại thông tin và gửi yêu cầu mới.";
      return;
    }
    approvalPoll = window.setTimeout(waitForApproval, 2000);
  } catch (_) {
    approvalPoll = window.setTimeout(waitForApproval, 4000);
  }
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  message.textContent = "Đang xác minh và gửi thông tin máy…";
  submit.disabled = true;

  try {
    const response = await fetch("/api/connection-requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.elements.username.value.trim(),
        password: form.elements.password.value,
        account_key: form.elements.account_key.value.trim(),
        device_id: getDeviceId(),
        device_name: deviceName(),
        device_type: deviceType()
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.message || data.error || "Không thể gửi yêu cầu kết nối");
      error.code = data.error || "";
      throw error;
    }
    form.elements.password.value = "";
    form.elements.account_key.value = "";
    message.textContent = data.status === "ALREADY_APPROVED"
      ? "Máy này đã được cấp quyền. Đang khởi tạo phiên đăng nhập…"
      : "Yêu cầu đã gửi. Chờ quản trị viên phê duyệt — hệ thống sẽ tự đăng nhập.";
    waitingApproval = true;
    waitForApproval();
  } catch (error) {
    if (error.code === "DEVICE_BROWSER_PROOF_REQUIRED") {
      createFreshDeviceIdentity();
      if (!retriedWithFreshIdentity) {
        retriedWithFreshIdentity = true;
        message.textContent = "Trình duyệt này chưa có chứng thực của thiết bị cũ. Đang tạo yêu cầu đăng ký mới…";
        window.setTimeout(() => form.requestSubmit(), 0);
      } else {
        message.textContent = "Không thể khôi phục chứng thực thiết bị cũ. Hãy tải lại trang và gửi yêu cầu đăng ký lại.";
      }
    } else message.textContent = error.message === "INVALID_ACCOUNT_ENROLLMENT_CREDENTIALS"
      ? "Tên đăng nhập, mật khẩu hoặc Account Key không đúng."
      : error.message;
  } finally {
    submit.disabled = waitingApproval;
  }
});

window.addEventListener("beforeunload", () => window.clearTimeout(approvalPoll));
