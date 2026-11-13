function localIsoDate() {
  const now = new Date();
  now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
  return now.toISOString().slice(0, 10);
}

const dateInput = document.querySelector("#log-date");
dateInput.value = localIsoDate();
dateInput.max = localIsoDate();

const viewState = { filter: "all", fingerprint: "", date: dateInput.value };
let selectedEvents = [];

const reasonText = {
  DEVICE_KEY_INVALID: "Khóa định danh thiết bị không hợp lệ",
  DEVICE_IP_NOT_ALLOWED: "IP nguồn không thuộc địa chỉ được cấp cho thiết bị",
  DEVICE_NOT_REGISTERED: "Thiết bị chưa được đăng ký",
  DEVICE_REGISTRATION_INACTIVE: "Thiết bị đã bị vô hiệu hóa",
  LOCATION_NOT_ALLOWED_FOR_DEVICE: "Vị trí truy cập không khớp",
  ROLE_LEVEL_INSUFFICIENT: "Vai trò chưa đủ quyền",
  DEVICE_TRUST_INSUFFICIENT: "Độ tin cậy thiết bị chưa đủ",
  LOCATION_LEVEL_INSUFFICIENT: "Mức tin cậy vùng mạng chưa đủ",
  AUTH_LEVEL_INSUFFICIENT: "Cần xác thực MFA ở cấp cao hơn",
  MFA_DEVICE_LOCKED: "Thiết bị bị khóa MFA sau 3 lần nhập sai mã",
  MFA_INVALID_CODE_THREE_TIMES: "Nhập sai mã MFA quá số lần cho phép",
  ACCESS_GRANTED: "Policy cho phép truy cập",
  OPA_UNAVAILABLE: "Không liên lạc được Policy Engine"
};

const eventTitles = {
  DEVICE_PROVISION_STARTED: "Bắt đầu cấp phát thiết bị",
  DEVICE_PROVISION_FINISHED: "Hoàn tất cấp phát thiết bị",
  DEVICE_PROVISIONED: "Đã cấp khóa định danh",
  DEVICE_PROVISION_PRESERVED: "Giữ nguyên khóa thiết bị",
  DEVICE_PROVISION_SKIPPED: "Bỏ qua thiết bị chưa đăng ký",
  LOGIN_PERMIT: "Đăng nhập thành công",
  LOGIN_DENY: "Đăng nhập bị từ chối",
  STEP_UP_PERMIT: "Đã nâng cấp xác thực MFA",
  STEP_UP_DENY: "Xác thực MFA không thành công",
  MFA_CHALLENGE_ISSUED: "Đã tạo yêu cầu MFA",
  MFA_DEVICE_LOCKED_AFTER_FAILURES: "Đã khóa thiết bị do sai mã MFA 3 lần",
  MFA_DEVICE_ACCESS_DENY: "Từ chối đọc vì thiết bị đang bị khóa MFA",
  MFA_DEVICE_UNLOCKED_BY_ADMIN: "Admin đã gỡ khóa MFA cho thiết bị",
  AUTHZ_ERROR: "Lỗi xác thực truy cập",
  DEVICE_ENROLLED: "Đã cấp phát thiết bị mới",
  DEVICE_REENROLLED: "Đã đăng ký lại thiết bị",
  DEVICE_REVOKED: "Đã thu hồi thiết bị",
  DEVICE_DELETED: "Đã xoá vĩnh viễn thiết bị",
  DEVICE_DISCOVERED: "Phát hiện thiết bị mới chờ phê duyệt",
  DEVICE_CONNECTION_REQUESTED: "Thiết bị gửi yêu cầu kết nối",
  DEVICE_CONNECTION_APPROVED: "Đã duyệt yêu cầu kết nối",
  DEVICE_BLOCKED: "Đã chặn thiết bị",
  DEVICE_IP_UPDATED: "Đã cập nhật IP được phép của thiết bị",
  STORED_DOCUMENT_UPLOADED: "Đã tải tài liệu vào phân vùng",
  STORED_DOCUMENT_READ: "Đã đọc tài liệu từ phân vùng",
  ENROLLMENT_CODE_ISSUED: "Đã cấp mã đăng ký một lần",
  USER_CREATED: "Đã tạo tài khoản truy cập",
  USER_DELETED: "Đã xóa vĩnh viễn tài khoản",
  USER_DEVICE_ASSIGNED: "Đã gán tài khoản với thiết bị",
  USER_DEVICE_UNASSIGNED: "Đã gỡ gán tài khoản khỏi thiết bị",
  MAC_CAPTURE_SETTING_CHANGED: "Đã thay đổi cài đặt thu thập MAC",
  AUDIT_LOG_SAVED: "Đã lưu riêng nhật ký audit",
  ADMIN_PASSWORD_CONFIGURED: "Đã thiết lập mật khẩu quản trị"
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;"
  })[character]);
}

function formatTime(seconds) {
  if (!seconds) return "—";

  return new Date(seconds * 1000).toLocaleString("vi-VN", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    day: "2-digit", month: "2-digit"
  });
}

function isDeviceEvent(event) {
  return (event.event_type ?? "").startsWith("DEVICE_PROVISION");
}

function isMfaEvent(event) {
  const type = event.event_type ?? "";
  return event.effect === "STEP_UP" || type.includes("MFA") || type.includes("STEP_UP");
}

function eventKind(event) {
  if (event.effect === "PERMIT") return "permit";
  if (event.effect === "STEP_UP") return "step";
  if (event.effect === "DENY" || /DENY|ERROR/.test(event.event_type ?? "")) return "deny";
  return "info";
}

function eventTitle(event) {
  if (event.event_type === "AUTHZ_DECISION") {
    if (event.effect === "PERMIT") return "Cho phép truy cập";
    if (event.effect === "STEP_UP") return "Yêu cầu MFA bổ sung";
    return "Từ chối truy cập";
  }

  return eventTitles[event.event_type] ?? event.event_type ?? "Sự kiện hệ thống";
}

function eventDetail(event) {
  return [
    event.reason_code && (reasonText[event.reason_code] ?? event.reason_code),
    event.username && `Người dùng ${event.username}`,
    event.device_id && `Thiết bị ${event.device_id}`,
    event.source_ip && `IP ${event.source_ip}`
  ].filter(Boolean).join(" · ") || "Sự kiện vận hành hệ thống";
}

function visibleEvents(events) {
  return events.filter(event => {
    if (viewState.filter === "all") return true;
    if (viewState.filter === "device") return isDeviceEvent(event);
    if (viewState.filter === "mfa") return isMfaEvent(event);
    return !isDeviceEvent(event) && !isMfaEvent(event);
  });
}

function renderEvents(events) {
  const container = document.querySelector("#log-list");
  const list = visibleEvents(events);

  if (!list.length) {
    container.innerHTML = '<p class="empty-state">Chưa có sự kiện phù hợp.</p>';
    return;
  }

  container.innerHTML = list.slice().reverse().map(event => {
    const kind = eventKind(event);
    const effect = event.effect ?? (event.event_type ?? "INFO").replace("DEVICE_PROVISION_", "");
    const chips = [
      event.location_id && `Vùng: ${event.location_id}`,
      event.resource_id && `Tài nguyên: ${event.resource_id}`,
      event.rule_id && `Rule: ${event.rule_id}`,
      event.trust_level && `Trust: ${event.trust_level}`
    ].filter(Boolean);

    return `
      <article class="log-event log-event--${kind}">
        <i class="log-event__dot"></i>
        <div class="log-event__main">
          <div class="log-event__title">${escapeHtml(eventTitle(event))}</div>
          <div class="log-event__detail">${escapeHtml(eventDetail(event))}</div>
          <div class="log-event__chips">
            ${chips.map(chip => `<span class="event-chip">${escapeHtml(chip)}</span>`).join("")}
          </div>
        </div>
        <div class="log-event__side">
          <div class="log-event__time">${formatTime(event.timestamp_epoch)}</div>
          <span class="effect-pill">${escapeHtml(effect)}</span>
        </div>
      </article>`;
  }).join("");
}

function updateMetrics(summary) {
  document.querySelector("#total-events").textContent = summary.total;
  document.querySelector("#permit-events").textContent = summary.permits;
  document.querySelector("#deny-events").textContent = summary.denies + summary.errors;
  document.querySelector("#step-up-events").textContent = summary.step_ups;
}

function setConnection(isOnline) {
  const connection = document.querySelector("#connection-status");
  connection.classList.toggle("service-status--offline", !isOnline);
  connection.innerHTML = `<i class="status-dot"></i>${isOnline ? "ZTAS trực tuyến" : "Mất kết nối"}`;
}

async function refreshLogs() {
  try {
    const query = new URLSearchParams({ limit: "200", date: viewState.date });
    const response = await fetch(`/api/audit?${query}`, { cache: "no-store" });
    if (!response.ok) throw new Error("Không lấy được log");

    const data = await response.json();
    selectedEvents = data.events ?? [];
    const fingerprint = JSON.stringify(data.events);

    updateMetrics(data.summary);
    if (fingerprint !== viewState.fingerprint) {
      viewState.fingerprint = fingerprint;
      renderEvents(data.events);
    }

    setConnection(true);
    document.querySelector("#last-updated").textContent =
      `Cập nhật ${new Date().toLocaleTimeString("vi-VN")}`;
  } catch {
    setConnection(false);
  }
}

document.querySelectorAll(".log-filter__button").forEach(button => {
  button.addEventListener("click", () => {
    viewState.filter = button.dataset.filter;
    document.querySelectorAll(".log-filter__button").forEach(item => {
      item.classList.toggle("log-filter__button--active", item === button);
    });
    viewState.fingerprint = "";
    refreshLogs();
  });
});

dateInput.addEventListener("change", () => {
  if (!dateInput.value) return;
  viewState.date = dateInput.value;
  viewState.fingerprint = "";
  refreshLogs();
});

document.querySelector("#save-log-button").addEventListener("click", async event => {
  const button = event.currentTarget;
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = "Đang lưu…";

  try {
    const response = await fetch("/api/audit/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ date: viewState.date })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || body.error || "Không thể lưu log");

    const content = JSON.stringify({
      date: viewState.date,
      retention: "saved-separately",
      events: selectedEvents
    }, null, 2);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    link.download = `ztas-audit-${viewState.date}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    button.textContent = "Đã lưu & tải";
  } catch (error) {
    button.textContent = error.message;
  } finally {
    button.disabled = false;
    setTimeout(() => { button.textContent = originalLabel; }, 2500);
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
  sessionStorage.removeItem("ztas_admin_token");
  location.assign("/admin/login");
});

refreshLogs();
setInterval(refreshLogs, 1000);
