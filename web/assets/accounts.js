let currentUser = "";
let userToDelete = "";
let adminToken = sessionStorage.getItem("ztas_admin_token") ?? "";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;"
  })[character]);
}

function roleLabel(role) {
  return ({ admin: "Quản trị viên", employee: "Nhân viên", manager: "Quản lý", engineer: "Kỹ sư", guest: "Khách" })[role] ?? role;
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
  const container = document.querySelector("#account-list");
  if (!users.length) {
    container.innerHTML = '<p class="empty-state">Chưa có tài khoản truy cập.</p>';
    return;
  }

  container.innerHTML = `<table class="account-table"><thead><tr><th>Tên đăng nhập</th><th>Vai trò</th><th>Thiết bị được gán</th><th>Phiên truy cập</th><th>Thao tác</th></tr></thead><tbody>${users.map(user => {
    const devices = user.allowed_device_ids ?? [];
    const devicesText = devices.length ? devices.join(", ") : "Chưa gán thiết bị";
    const session = user.temporary_session_minutes > 0 ? `Tạm thời ${user.temporary_session_minutes} phút` : "Không giới hạn theo thời gian";
    const isCurrent = user.username === currentUser;
    return `<tr><td><strong>${escapeHtml(user.username)}</strong></td><td><span class="role-badge role-badge--${escapeHtml(user.role)}">${escapeHtml(roleLabel(user.role))}</span></td><td class="account-table__devices">${escapeHtml(devicesText)}</td><td>${escapeHtml(session)}</td><td class="account-table__actions">${isCurrent ? '<span class="account-self">Phiên hiện tại</span>' : `<button class="button button--danger-outline button--small" data-delete-user="${escapeHtml(user.username)}">Xóa</button>`}</td></tr>`;
  }).join("")}</tbody></table>`;

  container.querySelectorAll("[data-delete-user]").forEach(button => button.addEventListener("click", () => openDeleteDialog(button.dataset.deleteUser)));
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
    renderUsers(data.users ?? []);
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

document.querySelectorAll("[data-close-dialog]").forEach(button => button.addEventListener("click", () => closeDialog(button.dataset.closeDialog)));
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
