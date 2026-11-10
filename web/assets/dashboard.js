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
let deviceToDelete = null;
let issuedCredential = null;
let assignableUsers = [];

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

function assignedAccounts(device) {
  const accounts = device.assigned_accounts ?? [];
  if (!accounts.length) return '<span class="account-empty">Chưa gán</span>';

  return accounts.map(account => `
    <span class="account-chip" title="Role: ${escapeHtml(account.role)}${account.scope === "all" ? " · toàn hệ thống" : ""}">
      ${escapeHtml(account.username)}<small>${escapeHtml(account.role)}${account.scope === "all" ? " · all" : ""}</small>
    </span>`).join("");
}

function renderDeviceCards(devices) {
  const container = document.querySelector("#device-list");

  if (!devices.length) {
    container.innerHTML = '<p class="empty-state">Chưa có thiết bị trong policy.</p>';
    return;
  }

  const rows = devices
    .slice()
    .sort((left, right) => orderByStatus[left.status] - orderByStatus[right.status])
    .map(device => {
      const info = statusInfo[device.status] ?? statusInfo.UNIDENTIFIED;
      const dotClass = info.cardClass === "step-up"
        ? "warning"
        : info.cardClass === "unidentified" ? "danger" : "success";

      return `
        <tr>
          <td class="device-table__device"><i class="status-dot status-dot--${dotClass}"></i><strong>${escapeHtml(device.id)}</strong></td>
          <td><span class="device-status device-status--${info.cardClass}">${info.label}</span></td>
          <td><span class="device-zone">${escapeHtml(device.location_id)}</span></td>
          <td><span class="trust-value">${escapeHtml(device.trust_level)}/5</span></td>
          <td class="device-table__accounts">${assignedAccounts(device)}</td>
          <td class="device-table__activity"><strong>${lastActivity(device)}</strong><span>${formatTime(device.last_seen)}</span></td>
          <td class="device-table__actions">
            ${device.registered
              ? `<button class="button button--secondary button--small" data-revoke-device="${escapeHtml(device.id)}">Thu hồi</button>`
              : `<button class="button button--secondary button--small" data-reenroll-device="${escapeHtml(device.id)}">Đăng ký lại</button>`}
            <button class="button button--danger-outline button--small" data-delete-device="${escapeHtml(device.id)}">Xoá</button>
          </td>
        </tr>`;
    })
    .join("");

  container.innerHTML = `
    <div class="device-table-wrap">
      <table class="device-table">
        <thead><tr><th>Thiết bị</th><th>Trạng thái Zero Trust</th><th>Vùng mạng</th><th>Độ tin cậy</th><th>Tài khoản được gán</th><th>Hoạt động gần nhất</th><th>Thao tác</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
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

  container.querySelectorAll("[data-delete-device]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openDeleteDialog(button.dataset.deleteDevice));
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

function renderDataZones(zones) {
  const container = document.querySelector("#data-zone-list");
  if (!zones.length) {
    container.innerHTML = '<p class="empty-state">Chưa có vùng dữ liệu trong CSDL.</p>';
    return;
  }

  container.innerHTML = `
    <table class="data-zone-table">
      <thead><tr><th>Vùng dữ liệu</th><th>Độ nhạy cảm</th><th>Số tài liệu</th><th>Mô tả</th></tr></thead>
      <tbody>${zones.map(zone => `
        <tr>
          <td><strong>${escapeHtml(zone.name)}</strong><span class="zone-id">${escapeHtml(zone.id)}</span></td>
          <td><span class="sensitivity sensitivity--${escapeHtml(zone.sensitivity)}">${escapeHtml(zone.sensitivity)}</span></td>
          <td>${escapeHtml(zone.document_count)}</td>
          <td class="data-zone-table__description">${escapeHtml(zone.description)}</td>
        </tr>`).join("")}</tbody>
    </table>`;
}

function renderConnectionRequests(requests) {
  const container = document.querySelector("#connection-request-list");
  const count = document.querySelector("#pending-request-count");
  count.textContent = `${requests.length} yêu cầu chờ`;

  if (!requests.length) {
    container.innerHTML = '<p class="empty-state">Không có yêu cầu kết nối đang chờ phê duyệt.</p>';
    return;
  }

  container.innerHTML = `
    <table class="connection-request-table">
      <thead><tr><th>Thiết bị yêu cầu</th><th>Vùng mạng khai báo</th><th>IP nguồn</th><th>Lần đầu / gần nhất</th><th>Số lần thử</th><th>Thông tin máy khách</th><th>Thao tác</th></tr></thead>
      <tbody>${requests.map(request => `
        <tr>
          <td><strong>${escapeHtml(request.device_id)}</strong><span class="request-state"><i class="status-dot status-dot--warning"></i>Chờ phân loại</span></td>
          <td><span class="device-zone">${escapeHtml(request.location_id)}</span></td>
          <td><span class="device-zone">${escapeHtml(request.source_ip)}</span></td>
          <td class="request-time"><strong>${formatTime(request.first_seen)}</strong><span>Cập nhật: ${formatTime(request.last_seen)}</span></td>
          <td>${escapeHtml(request.attempt_count)}</td>
          <td class="request-agent" title="${escapeHtml(request.user_agent)}">${escapeHtml(request.user_agent)}</td>
          <td><button class="button button--primary button--small" data-approve-request="${escapeHtml(request.device_id)}" data-request-location="${escapeHtml(request.location_id)}">Phân loại &amp; cấp quyền</button></td>
        </tr>`).join("")}</tbody>
    </table>`;

  container.querySelectorAll("[data-approve-request]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openEnrollDialog(
        button.dataset.approveRequest,
        button.dataset.requestLocation
      ));
    });
  });
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

async function refreshDataZones() {
  try {
    const response = await fetch("/api/data-zones", { cache: "no-store" });
    if (!response.ok) throw new Error("Không lấy được vùng dữ liệu");
    const data = await response.json();
    renderDataZones(data.zones ?? []);
  } catch {
    document.querySelector("#data-zone-list").innerHTML =
      '<p class="empty-state">Không thể tải vùng dữ liệu CSDL.</p>';
  }
}

async function refreshConnectionRequests() {
  const container = document.querySelector("#connection-request-list");
  try {
    const response = await fetch("/api/device-requests", { cache: "no-store" });
    if (!response.ok) throw new Error("Không lấy được yêu cầu kết nối");
    const data = await response.json();
    renderConnectionRequests(data.requests ?? []);
  } catch {
    container.innerHTML = '<p class="empty-state">Không thể tải yêu cầu kết nối.</p>';
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

async function loadAssignableUsers() {
  const selector = document.querySelector("#enroll-device-form select[name=assigned_username]");
  try {
    const response = await fetch("/api/users", { headers: apiHeaders() });
    const data = await parseResponse(response);
    assignableUsers = data.users ?? [];
    selector.innerHTML = [
      '<option value="">Chọn tài khoản</option>',
      ...assignableUsers.map(user =>
        `<option value="${escapeHtml(user.username)}">${escapeHtml(user.username)} — ${escapeHtml(user.role)}</option>`
      )
    ].join("");
  } catch {
    selector.innerHTML = '<option value="">Không tải được tài khoản</option>';
  }
}

async function openEnrollDialog(deviceId = "", locationId = "lab-network") {
  const form = document.querySelector("#enroll-device-form");
  form.reset();
  form.elements.device_id.value = deviceId;
  form.elements.trust_level.value = "3";
  form.elements.location_id.value = [...form.elements.location_id.options]
    .some(option => option.value === locationId)
      ? locationId
      : "lab-network";
  document.querySelector("#enroll-device-message").textContent = "";
  await loadAssignableUsers();
  showDialog("enroll-device-dialog");
}

function openRevokeDialog(deviceId) {
  deviceToRevoke = deviceId;
  document.querySelector("#revoke-device-text").textContent =
    `Bạn sắp thu hồi ${deviceId}. Thiết bị sẽ không thể tiếp tục truy cập bằng khóa hiện tại.`;
  document.querySelector("#revoke-device-message").textContent = "";
  showDialog("revoke-device-dialog");
}

function openDeleteDialog(deviceId) {
  deviceToDelete = deviceId;
  document.querySelector("#delete-device-text").textContent =
    `Bạn sắp xoá vĩnh viễn ${deviceId} khỏi hệ thống PoC.`;
  document.querySelector("#delete-device-message").textContent = "";
  showDialog("delete-device-dialog");
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
        location_id: form.elements.location_id.value,
        assigned_username: form.elements.assigned_username.value
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
    refreshConnectionRequests();
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

document.querySelector("#confirm-delete-device").addEventListener("click", async () => {
  const message = document.querySelector("#delete-device-message");
  if (!deviceToDelete) return;
  message.textContent = "Đang xoá vĩnh viễn thiết bị…";

  try {
    const response = await fetch(
      `/api/devices/permanent?id=${encodeURIComponent(deviceToDelete)}`,
      { method: "DELETE", headers: apiHeaders() }
    );
    await parseResponse(response);
    closeDialog("delete-device-dialog");
    deviceToDelete = null;
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

document.querySelector("#logout-button").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
  adminToken = "";
  sessionStorage.removeItem("ztas_admin_token");
  location.assign("/admin/login");
});

refreshDashboard();
refreshDataZones();
refreshConnectionRequests();
setInterval(() => {
  refreshDashboard();
  refreshDataZones();
  refreshConnectionRequests();
}, 1000);
