const statusInfo = {
  IDENTIFIED: {
    label: "Đã xác định",
    cardClass: "identified",
    description: "Đã đăng ký và có định danh thiết bị hợp lệ."
  },
  UNIDENTIFIED: {
    label: "Chưa xác định",
    cardClass: "unidentified",
    description: "Chưa đăng ký hoặc chưa xác minh được khóa thiết bị."
  },
  STEP_UP: {
    label: "Cần xác thực thêm",
    cardClass: "step-up",
    description: "Thiết bị hợp lệ, cần MFA ở cấp cao hơn để tiếp tục."
  }
};

const orderByStatus = { STEP_UP: 0, UNIDENTIFIED: 1, IDENTIFIED: 2 };
let adminToken = sessionStorage.getItem("ztas_admin_token") ?? "";
let pendingAdminAction = null;
let deviceToRevoke = null;
let issuedCredential = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;"
  })[character]);
}

function formatTime(seconds) {
  if (!seconds) return "Chưa có hoạt động";

  return new Date(seconds * 1000).toLocaleString("vi-VN", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    day: "2-digit", month: "2-digit"
  });
}

function lastActivity(device) {
  const event = device.last_event;
  if (!event) return "Sẵn sàng chờ yêu cầu truy cập";

  if (event.event_type === "AUTHZ_DECISION") {
    if (event.effect === "PERMIT") return "Truy cập gần nhất được cho phép";
    if (event.effect === "STEP_UP") return "Yêu cầu gần nhất cần MFA";
    return "Yêu cầu gần nhất bị từ chối";
  }

  if (event.event_type === "DEVICE_PROVISION_SKIPPED") {
    return "Không được cấp khóa vì chưa đăng ký";
  }

  return "Đã được hệ thống ghi nhận";
}

function updateText(id, value) {
  document.querySelector(id).textContent = value;
}

function renderDeviceCards(devices) {
  const container = document.querySelector("#device-list");

  if (!devices.length) {
    container.innerHTML = '<p class="empty-state">Chưa có thiết bị trong policy.</p>';
    return;
  }

  const cards = devices
    .slice()
    .sort((left, right) => orderByStatus[left.status] - orderByStatus[right.status])
    .map(device => {
      const info = statusInfo[device.status] ?? statusInfo.UNIDENTIFIED;

      return `
        <article class="device-card device-card--${info.cardClass}">
          <div class="device-card__top">
            <div class="device-card__id">
              <i class="status-dot status-dot--${info.cardClass === "step-up" ? "warning" : info.cardClass === "unidentified" ? "danger" : "success"}"></i>
              <span>${escapeHtml(device.id)}</span>
            </div>
            <span class="status-pill">${info.label}</span>
          </div>
          <p class="device-card__description">${info.description}</p>
          <div class="device-facts">
            <div><span>Vùng mạng</span><strong>${escapeHtml(device.location_id)}</strong></div>
            <div><span>Độ tin cậy</span><strong>${escapeHtml(device.trust_level)}/5</strong></div>
          </div>
          <p class="device-card__last">${lastActivity(device)} · ${formatTime(device.last_seen)}</p>
          <div class="device-card__actions">
            ${device.registered
              ? `<button class="button button--secondary button--small" data-revoke-device="${escapeHtml(device.id)}">Thu hồi</button>`
              : `<button class="button button--secondary button--small" data-reenroll-device="${escapeHtml(device.id)}">Đăng ký lại</button>`}
          </div>
        </article>`;
    })
    .join("");

  container.innerHTML = cards;
  container.querySelectorAll("[data-revoke-device]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openRevokeDialog(button.dataset.revokeDevice));
    });
  });

  container.querySelectorAll("[data-reenroll-device]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openEnrollDialog(button.dataset.reenrollDevice));
    });
  });
}

function updateDonut(summary) {
  const total = summary.total;
  const donut = document.querySelector("#device-donut");

  if (!total) {
    donut.style.background = "#e8edf4";
    return;
  }

  const identifiedEnd = summary.identified / total * 360;
  const unidentifiedEnd = identifiedEnd + summary.unidentified / total * 360;

  donut.style.background = `conic-gradient(
    #0a9561 0deg ${identifiedEnd}deg,
    #d7405a ${identifiedEnd}deg ${unidentifiedEnd}deg,
    #c17b00 ${unidentifiedEnd}deg 360deg
  )`;
}

function renderDashboard(data) {
  const { summary, devices } = data;

  updateText("#total-devices", summary.total);
  updateText("#identified-devices", summary.identified);
  updateText("#unidentified-devices", summary.unidentified);
  updateText("#step-up-devices", summary.step_up);
  updateText("#donut-total", summary.total);
  updateText("#legend-identified", summary.identified);
  updateText("#legend-unidentified", summary.unidentified);
  updateText("#legend-step-up", summary.step_up);
  updateText("#active-device-count", `${devices.filter(device => device.last_seen > 0).length} thiết bị`);
  updateDonut(summary);
  renderDeviceCards(devices);
}

function setConnection(isOnline) {
  const connection = document.querySelector("#connection-status");
  const ztasState = document.querySelector("#ztas-state");

  connection.classList.toggle("service-status--offline", !isOnline);
  connection.innerHTML = `<i class="status-dot"></i>${isOnline ? "ZTAS trực tuyến" : "Mất kết nối"}`;
  ztasState.textContent = isOnline ? "Trực tuyến" : "Không kết nối";
  ztasState.classList.toggle("text-success", isOnline);
}

async function refreshDashboard() {
  try {
    const response = await fetch("/api/devices", { cache: "no-store" });
    if (!response.ok) throw new Error("Không lấy được dữ liệu thiết bị");

    const data = await response.json();
    renderDashboard(data);
    setConnection(true);
    updateText("#last-updated", `Cập nhật ${new Date().toLocaleTimeString("vi-VN")}`);
  } catch {
    setConnection(false);
  }
}

function showDialog(id) {
  document.querySelector(`#${id}`).showModal();
}

function closeDialog(id) {
  document.querySelector(`#${id}`).close();
}

function requireAdmin(action) {
  if (adminToken) {
    action();
    return;
  }

  pendingAdminAction = action;
  document.querySelector("#admin-login-message").textContent = "";
  showDialog("admin-login-dialog");
}

function apiHeaders() {
  return {
    "Authorization": `Bearer ${adminToken}`,
    "Content-Type": "application/json"
  };
}

function openEnrollDialog(deviceId = "") {
  const form = document.querySelector("#enroll-device-form");
  form.reset();
  form.elements.device_id.value = deviceId;
  form.elements.trust_level.value = "3";
  form.elements.location_id.value = "lab-network";
  document.querySelector("#enroll-device-message").textContent = "";
  showDialog("enroll-device-dialog");
}

function openRevokeDialog(deviceId) {
  deviceToRevoke = deviceId;
  document.querySelector("#revoke-device-text").textContent =
    `Bạn sắp thu hồi ${deviceId}. Thiết bị sẽ không thể tiếp tục truy cập bằng khóa hiện tại.`;
  document.querySelector("#revoke-device-message").textContent = "";
  showDialog("revoke-device-dialog");
}

async function parseResponse(response) {
  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      adminToken = "";
      sessionStorage.removeItem("ztas_admin_token");
    }
    throw new Error(body.message || body.error || "Thao tác không thành công");
  }

  return body;
}

document.querySelector("#add-device-button").addEventListener("click", () => {
  requireAdmin(() => openEnrollDialog());
});

document.querySelector("#admin-login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("#admin-login-message");
  message.textContent = "Đang xác thực…";

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.elements.username.value,
        password: form.elements.password.value
      })
    });
    const data = await parseResponse(response);

    if (data.subject?.role !== "admin") {
      throw new Error("Tài khoản này không có role admin");
    }

    adminToken = data.access_token;
    sessionStorage.setItem("ztas_admin_token", adminToken);
    closeDialog("admin-login-dialog");
    const action = pendingAdminAction;
    pendingAdminAction = null;
    action?.();
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#enroll-device-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("#enroll-device-message");
  message.textContent = "Đang cấp phát thiết bị…";

  try {
    const response = await fetch("/api/devices", {
      method: "POST",
      headers: apiHeaders(),
      body: JSON.stringify({
        device_id: form.elements.device_id.value.trim(),
        trust_level: Number(form.elements.trust_level.value),
        location_id: form.elements.location_id.value
      })
    });
    const data = await parseResponse(response);
    issuedCredential = {
      ...data.device,
      device_key: data.device_key
    };
    document.querySelector("#issued-device-key").value = data.device_key;
    closeDialog("enroll-device-dialog");
    showDialog("device-key-dialog");
    refreshDashboard();
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#confirm-revoke-device").addEventListener("click", async () => {
  const message = document.querySelector("#revoke-device-message");
  if (!deviceToRevoke) return;
  message.textContent = "Đang thu hồi thiết bị…";

  try {
    const response = await fetch(
      `/api/devices?id=${encodeURIComponent(deviceToRevoke)}`,
      { method: "DELETE", headers: apiHeaders() }
    );
    await parseResponse(response);
    closeDialog("revoke-device-dialog");
    deviceToRevoke = null;
    refreshDashboard();
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#copy-device-key").addEventListener("click", async () => {
  const input = document.querySelector("#issued-device-key");
  await navigator.clipboard.writeText(input.value);
  document.querySelector("#copy-device-key").textContent = "Đã sao chép";
});

document.querySelector("#download-device-env").addEventListener("click", () => {
  if (!issuedCredential) return;
  const content = [
    `DEVICE_ID=${issuedCredential.id}`,
    `DEVICE_KEY=${issuedCredential.device_key}`,
    `LOCATION_ID=${issuedCredential.location_id}`,
    ""
  ].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  link.download = `${issuedCredential.id}.env`;
  link.click();
  URL.revokeObjectURL(link.href);
});

document.querySelectorAll("[data-close-dialog]").forEach(button => {
  button.addEventListener("click", () => closeDialog(button.dataset.closeDialog));
});

document.querySelector("#device-key-dialog").addEventListener("close", () => {
  issuedCredential = null;
  document.querySelector("#issued-device-key").value = "";
  document.querySelector("#copy-device-key").textContent = "Sao chép key";
});

refreshDashboard();
setInterval(refreshDashboard, 1000);
