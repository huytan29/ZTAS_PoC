let currentUser = "";
let userToDelete = "";
let adminToken = sessionStorage.getItem("ztas_admin_token") ?? "";
let managedUsers = [];
let accountToAssign = null;
let registeredDevices = [];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;"
  })[character]);
}

function roleLabel(role) {
  return ({ admin: "Quản trị viên", employee: "Nhân viên", manager: "Quản lý", engineer: "Kỹ sư", guest: "Khách" })[role] ?? role;
}

function rolePermission(role) {
  const permissions = {
    guest: "Quyền hệ thống: tài liệu công khai (cấp 1).",
    employee: "Quyền hệ thống: đọc tài liệu cấp 1–2 khi thiết bị đáp ứng policy.",
    manager: "Quyền hệ thống: đọc tài liệu cấp 1–3 khi thiết bị đáp ứng policy.",
    engineer: "Quyền hệ thống: đọc tài liệu cấp 1–4 khi thiết bị, vị trí và MFA đáp ứng policy.",
    admin: "Quyền hệ thống: đọc toàn bộ tài liệu cấp 1–5 sau khi tài khoản và thiết bị được cấp phát hợp lệ."
  };
  return permissions[role] ?? "Quyền được xác định bởi policy hệ thống.";
}

function rolePermissionShort(role) {
  return ({ guest: "Cấp 1", employee: "Cấp 1–2", manager: "Cấp 1–3", engineer: "Cấp 1–4", admin: "Cấp 1–5" })[role] ?? "Theo policy";
}

function apiHeaders(json = false) {
  const headers = json ? { "Content-Type": "application/json" } : {};
  if (adminToken) headers.Authorization = `Bearer ${adminToken}`;
  return headers;
}

async function parseResponse(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message || body.error || "Thao tác không thành công");
  return body;
}

function renderUsers(users) {
  document.querySelector("#account-count").textContent = `${users.length} tài khoản`;
  document.querySelector("#metric-total-users").textContent = users.length;
  document.querySelector("#metric-bound-users").textContent = users.filter(user => (user.allowed_device_ids ?? []).length > 0).length;
  document.querySelector("#metric-admin-users").textContent = users.filter(user => user.role === "admin").length;
  const container = document.querySelector("#account-list");
  if (!users.length) {
    container.innerHTML = '<p class="empty-state">Chưa có tài khoản truy cập.</p>';
    return;
  }

  container.innerHTML = `<table class="account-table"><thead><tr><th>Tên đăng nhập</th><th>Vai trò</th><th>Quyền hệ thống</th><th>Thiết bị được gán</th><th>Phiên truy cập</th><th>Thao tác</th></tr></thead><tbody>${users.map(user => {
    const devices = user.allowed_device_ids ?? [];
    const devicesText = devices.length ? devices.join(", ") : "Chưa gán thiết bị";
    const session = user.temporary_session_minutes > 0 ? `Tạm thời ${user.temporary_session_minutes} phút` : "Không giới hạn theo thời gian";
    const isCurrent = user.username === currentUser;
    const hasGlobalScope = devices.includes("*");
    return `<tr><td><strong>${escapeHtml(user.username)}</strong></td><td><span class="role-badge role-badge--${escapeHtml(user.role)}">${escapeHtml(roleLabel(user.role))}</span></td><td class="account-table__permission">${escapeHtml(rolePermissionShort(user.role))}</td><td class="account-table__devices">${escapeHtml(devicesText)}</td><td>${escapeHtml(session)}</td><td class="account-table__actions"><div class="account-action-group">${hasGlobalScope ? '<span class="account-self">Phạm vi toàn hệ thống</span>' : `<button class="button button--secondary button--small" data-assign-user="${escapeHtml(user.username)}">Gán thiết bị</button>`}${isCurrent ? '<span class="account-self">Phiên hiện tại</span>' : `<button class="button button--danger-outline button--small" data-delete-user="${escapeHtml(user.username)}">Xóa</button>`}</div></td></tr>`;
  }).join("")}</tbody></table>`;

  container.querySelectorAll("[data-delete-user]").forEach(button => button.addEventListener("click", () => openDeleteDialog(button.dataset.deleteUser)));
  container.querySelectorAll("[data-assign-user]").forEach(button => button.addEventListener("click", () => openAssignmentDialog(button.dataset.assignUser)));
}

function setConnection(online) {
  const connection = document.querySelector("#connection-status");
  connection.classList.toggle("service-status--offline", !online);
  connection.innerHTML = `<i class="status-dot"></i>${online ? "ZTAS trực tuyến" : "Mất kết nối"}`;
}

async function refreshUsers() {
  try {
    const response = await fetch("/api/users", { cache: "no-store", headers: apiHeaders() });
    const data = await parseResponse(response);
    managedUsers = data.users ?? [];
    renderUsers(managedUsers);
    setConnection(true);
    document.querySelector("#last-updated").textContent = `Cập nhật ${new Date().toLocaleTimeString("vi-VN")}`;
  } catch (error) {
    document.querySelector("#account-list").innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
    setConnection(false);
  }
}

function showDialog(id) { document.querySelector(`#${id}`).showModal(); }
function closeDialog(id) { document.querySelector(`#${id}`).close(); }

function openDeleteDialog(username) {
  userToDelete = username;
  document.querySelector("#delete-user-text").textContent = `Bạn sắp xóa vĩnh viễn tài khoản ${username}.`;
  document.querySelector("#delete-user-message").textContent = "";
  showDialog("delete-user-dialog");
}

async function loadRegisteredDevices() {
  const response = await fetch("/api/registered-devices", { cache: "no-store", headers: apiHeaders() });
  const data = await parseResponse(response);
  registeredDevices = data.devices ?? [];
}

function renderAssignmentDialog() {
  if (!accountToAssign) return;
  const devices = accountToAssign.allowed_device_ids ?? [];
  document.querySelector("#assignment-user-label").textContent = `${accountToAssign.username} · ${roleLabel(accountToAssign.role)}`;
  document.querySelector("#assignment-permission").innerHTML = `<strong>Quyền do policy quyết định</strong>${escapeHtml(rolePermission(accountToAssign.role))}`;
  const list = document.querySelector("#assigned-device-list");
  list.innerHTML = devices.length ? devices.map(device => `<span class="assignment-chip">${escapeHtml(device)}<button type="button" data-unassign-device="${escapeHtml(device)}" title="Gỡ gán">×</button></span>`).join("") : '<span class="assignment-empty">Chưa gán thiết bị. Tài khoản chưa thể truy cập dữ liệu.</span>';
  list.querySelectorAll("[data-unassign-device]").forEach(button => button.addEventListener("click", () => unassignDevice(button.dataset.unassignDevice)));

  const selector = document.querySelector("#assignment-device-select");
  const available = registeredDevices.filter(device => !devices.includes(device.id));
  selector.innerHTML = ['<option value="">Chọn thiết bị đã đăng ký</option>', ...available.map(device => `<option value="${escapeHtml(device.id)}">${escapeHtml(device.id)} · Trust ${escapeHtml(device.trust_level)}/5 · ${escapeHtml(device.location_id)}</option>`)].join("");
  document.querySelector("#assign-device-button").disabled = !available.length;
}

async function openAssignmentDialog(username) {
  accountToAssign = managedUsers.find(user => user.username === username) ?? null;
  if (!accountToAssign) return;
  document.querySelector("#assignment-message").textContent = "";
  try {
    await loadRegisteredDevices();
    renderAssignmentDialog();
    showDialog("assignment-dialog");
  } catch (error) {
    alert(error.message);
  }
}

async function refreshAssignedAccount() {
  await refreshUsers();
  accountToAssign = managedUsers.find(user => user.username === accountToAssign?.username) ?? null;
  renderAssignmentDialog();
}

async function unassignDevice(deviceId) {
  if (!accountToAssign) return;
  const message = document.querySelector("#assignment-message");
  message.textContent = "Đang gỡ gán thiết bị…";
  try {
    const response = await fetch(`/api/user-device-assignments?username=${encodeURIComponent(accountToAssign.username)}&device_id=${encodeURIComponent(deviceId)}`, { method: "DELETE", headers: apiHeaders() });
    await parseResponse(response);
    message.textContent = "";
    await refreshAssignedAccount();
  } catch (error) { message.textContent = error.message; }
}

document.querySelector("#add-user-button").addEventListener("click", () => {
  const form = document.querySelector("#create-user-form");
  form.reset();
  form.elements.role.value = "employee";
  document.querySelector("#create-user-message").textContent = "";
  showDialog("create-user-dialog");
});

document.querySelector("#create-user-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("#create-user-message");
  message.textContent = "Đang tạo tài khoản…";
  try {
    const response = await fetch("/api/users", { method: "POST", headers: apiHeaders(true), body: JSON.stringify({ username: form.elements.username.value.trim(), role: form.elements.role.value }) });
    const data = await parseResponse(response);
    closeDialog("create-user-dialog");
    await refreshUsers();
    alert(`Đã tạo tài khoản ${data.user.username}. Mật khẩu khởi tạo: ptit@123`);
  } catch (error) { message.textContent = error.message; }
});

document.querySelector("#confirm-delete-user").addEventListener("click", async () => {
  if (!userToDelete) return;
  const message = document.querySelector("#delete-user-message");
  message.textContent = "Đang xóa vĩnh viễn tài khoản…";
  try {
    const response = await fetch(`/api/users?username=${encodeURIComponent(userToDelete)}`, { method: "DELETE", headers: apiHeaders() });
    await parseResponse(response);
    closeDialog("delete-user-dialog");
    userToDelete = "";
    await refreshUsers();
  } catch (error) { message.textContent = error.message; }
});

document.querySelector("#assign-device-button").addEventListener("click", async () => {
  if (!accountToAssign) return;
  const deviceId = document.querySelector("#assignment-device-select").value;
  const message = document.querySelector("#assignment-message");
  if (!deviceId) { message.textContent = "Chọn một thiết bị đã đăng ký."; return; }
  message.textContent = "Đang gán thiết bị…";
  try {
    const response = await fetch("/api/user-device-assignments", { method: "POST", headers: apiHeaders(true), body: JSON.stringify({ username: accountToAssign.username, device_id: deviceId }) });
    await parseResponse(response);
    message.textContent = "";
    await refreshAssignedAccount();
  } catch (error) { message.textContent = error.message; }
});

document.querySelectorAll("[data-close-dialog]").forEach(button => button.addEventListener("click", () => closeDialog(button.dataset.closeDialog)));
document.querySelector("#assignment-dialog").addEventListener("close", () => { accountToAssign = null; });
document.querySelector("#logout-button").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
  sessionStorage.removeItem("ztas_admin_token");
  location.assign("/admin/login");
});

(async () => {
  try {
    const response = await fetch("/api/me", { headers: apiHeaders() });
    const me = await parseResponse(response);
    currentUser = me.username ?? "";
  } catch { currentUser = ""; }
  refreshUsers();
})();
