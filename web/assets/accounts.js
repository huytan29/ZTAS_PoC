let currentUser = "";
let userToDelete = "";
let adminToken = sessionStorage.getItem("ztas_admin_token") ?? "";
let managedUsers = [];
let accountToAssign = null;
let registeredDevices = [];
let issuedAccountKey = "";
let userForDocumentPermissions = null;
let userForPasswordReset = "";
let userForOwnPasswordChange = "";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;"
  })[character]);
}

function roleLabel(role) {
  return ({ admin: "Quản trị kỹ thuật", business_admin: "Lãnh đạo được ủy quyền", employee: "Chuyên viên", manager: "Quản lý", engineer: "Kỹ sư", guest: "Khách" })[role] ?? role;
}

function rolePermission(role) {
  const permissions = {
    guest: "Quyền hệ thống: tài liệu công khai (cấp 1).",
    employee: "Quyền hệ thống: đọc tài liệu cấp 1–2 khi thiết bị đáp ứng policy.",
    manager: "Quyền hệ thống: đọc tài liệu cấp 1–3 khi thiết bị đáp ứng policy.",
    engineer: "Quyền hệ thống: đọc tài liệu cấp 1–4 khi thiết bị, vị trí và MFA đáp ứng policy.",
    admin: "Quyền kỹ thuật: quản lý hệ thống và đọc Cấp 1–2; không tự có quyền đọc tài liệu nghiệp vụ Cấp 3–5.",
    business_admin: "Quyền nghiệp vụ được ủy quyền: đọc cấp 1–5 trong phạm vi đơn vị/nhiệm vụ và khi thiết bị đáp ứng policy."
  };
  return permissions[role] ?? "Quyền được xác định bởi policy hệ thống.";
}

function rolePermissionShort(role) {
  return ({ guest: "Cấp 1", employee: "Cấp 1–2", manager: "Cấp 1–3", engineer: "Cấp 1–4", business_admin: "Cấp 1–5 theo phạm vi", admin: "Cấp 1–2 kỹ thuật" })[role] ?? "Theo policy";
}

function organizationLabel(organizationUnit) {
  return ({ "unit-a": "Đơn vị A", "unit-b": "Đơn vị B", "it-ops": "Khối kỹ thuật" })[organizationUnit] ?? organizationUnit;
}

function taskScopeLabel(tasks) {
  if ((tasks ?? []).includes("*")) return "Toàn bộ tài liệu trong phạm vi được ủy quyền";
  const labels = [];
  for (const task of tasks ?? []) {
    if (task === "public") labels.push("Tài liệu công khai");
    else if (task.startsWith("internal-")) labels.push("Tài liệu nội bộ");
    else if (task.startsWith("sensitive-")) labels.push("Tài liệu mật / nhạy cảm");
    else if (task.startsWith("secret-")) labels.push("Tài liệu bí mật");
    else if (task.startsWith("restricted-")) labels.push("Tài liệu hạn chế đặc biệt");
  }
  return [...new Set(labels)].join(", ") || "Quyền tự động theo vai trò";
}

function tasksForScope(scope, organizationUnit) {
  if (scope === "auto") return [];
  const suffix = organizationUnit.startsWith("unit-") ? organizationUnit.slice(5) : organizationUnit;
  const tasks = ["public"];
  if (["internal", "sensitive", "secret", "restricted"].includes(scope)) tasks.push(`internal-${suffix}`);
  if (["sensitive", "secret", "restricted"].includes(scope)) tasks.push(`sensitive-${suffix}`);
  if (["secret", "restricted"].includes(scope)) tasks.push(`secret-${suffix}`);
  if (scope === "restricted") tasks.push(`restricted-${suffix}`);
  return tasks;
}

function maximumDocumentLevel(role) {
  return ({ guest: 1, employee: 2, manager: 3, engineer: 4, business_admin: 5, admin: 2 })[role] ?? 0;
}

function scopeForTasks(tasks) {
  if ((tasks ?? []).includes("*")) return "restricted";
  const scopes = ["restricted", "secret", "sensitive", "internal", "public"];
  return scopes.find(scope => (tasks ?? []).some(task =>
    scope === "public" ? task === "public" : task.startsWith(`${scope}-`)
  )) ?? "public";
}

function scopeLevel(scope) {
  return ({ public: 1, internal: 2, sensitive: 3, secret: 4, restricted: 5 })[scope] ?? 0;
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
    const taskText = user.task_description || taskScopeLabel(user.assigned_tasks);
    const scope = `${organizationLabel(user.organization_unit || "unit-a")} · ${taskText}`;
    const passwordAction = isCurrent
      ? `<button class="button button--secondary button--small" data-change-own-password="${escapeHtml(user.username)}">Đổi mật khẩu</button>`
      : `<button class="button button--secondary button--small" data-reset-password="${escapeHtml(user.username)}">Đặt lại mật khẩu</button>`;
    return `<tr><td><strong>${escapeHtml(user.username)}</strong><small class="account-scope">${escapeHtml(scope)}</small></td><td><span class="role-badge role-badge--${escapeHtml(user.role)}">${escapeHtml(roleLabel(user.role))}</span></td><td class="account-table__permission">${escapeHtml(rolePermissionShort(user.role))}</td><td class="account-table__devices">${escapeHtml(devicesText)}</td><td>${escapeHtml(session)}</td><td class="account-table__actions"><div class="account-action-group">${hasGlobalScope ? '<span class="account-self">Phạm vi toàn hệ thống</span>' : `<button class="button button--secondary button--small" data-assign-user="${escapeHtml(user.username)}">Gán thiết bị</button>`}<button class="button button--secondary button--small" data-edit-document-permissions="${escapeHtml(user.username)}">Quyền tài liệu</button>${passwordAction}<button class="button button--secondary button--small" data-issue-account-key="${escapeHtml(user.username)}">Cấp lại key</button>${isCurrent ? '<span class="account-self">Phiên hiện tại</span>' : `<button class="button button--danger-outline button--small" data-delete-user="${escapeHtml(user.username)}">Xóa</button>`}</div></td></tr>`;
  }).join("")}</tbody></table>`;

  container.querySelectorAll("[data-delete-user]").forEach(button => button.addEventListener("click", () => openDeleteDialog(button.dataset.deleteUser)));
  container.querySelectorAll("[data-assign-user]").forEach(button => button.addEventListener("click", () => openAssignmentDialog(button.dataset.assignUser)));
  container.querySelectorAll("[data-edit-document-permissions]").forEach(button => button.addEventListener("click", () => openDocumentPermissionDialog(button.dataset.editDocumentPermissions)));
  container.querySelectorAll("[data-reset-password]").forEach(button => button.addEventListener("click", () => openPasswordResetDialog(button.dataset.resetPassword)));
  container.querySelectorAll("[data-change-own-password]").forEach(button => button.addEventListener("click", () => openOwnPasswordDialog(button.dataset.changeOwnPassword)));
  container.querySelectorAll("[data-issue-account-key]").forEach(button => button.addEventListener("click", () => issueAccountKey(button.dataset.issueAccountKey)));
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

function showAccountKey(username, key, rotated = false) {
  issuedAccountKey = key;
  document.querySelector("#issued-account-key").value = key;
  document.querySelector("#account-key-result-text").textContent = rotated
    ? `Account Key mới cho ${username}. Key cũ mất hiệu lực ngay; lưu và chuyển key mới qua kênh an toàn.`
    : `Account Key của ${username}. Key chỉ hiển thị một lần; lưu và chuyển cho đúng người dùng qua kênh an toàn.`;
  showDialog("account-key-result-dialog");
}

function openDeleteDialog(username) {
  userToDelete = username;
  document.querySelector("#delete-user-text").textContent = `Bạn sắp xóa vĩnh viễn tài khoản ${username}.`;
  document.querySelector("#delete-user-message").textContent = "";
  showDialog("delete-user-dialog");
}

function openPasswordResetDialog(username) {
  userForPasswordReset = username;
  document.querySelector("#password-reset-user-label").textContent =
    `Đặt lại mật khẩu của ${username} về mặc định ptit@123. Toàn bộ phiên đang đăng nhập của tài khoản này sẽ bị đăng xuất.`;
  document.querySelector("#password-reset-message").textContent = "";
  showDialog("password-reset-dialog");
}

document.querySelector("#confirm-password-reset").addEventListener("click", async () => {
  if (!userForPasswordReset) return;
  const message = document.querySelector("#password-reset-message");
  message.textContent = "Đang đặt lại mật khẩu…";
  try {
    const response = await fetch("/api/users/password", {
      method: "PUT",
      headers: apiHeaders(true),
      body: JSON.stringify({ username: userForPasswordReset })
    });
    const data = await parseResponse(response);
    closeDialog("password-reset-dialog");
    userForPasswordReset = "";
    alert(data.message);
  } catch (error) {
    message.textContent = error.message;
  }
});

function openOwnPasswordDialog(username) {
  userForOwnPasswordChange = username;
  const form = document.querySelector("#own-password-form");
  form.reset();
  document.querySelector("#own-password-message").textContent = "";
  showDialog("own-password-dialog");
  form.elements.current_password.focus();
}

document.querySelector("#own-password-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("#own-password-message");
  if (form.elements.new_password.value !== form.elements.confirm_password.value) {
    message.textContent = "Hai lần nhập mật khẩu mới chưa khớp.";
    return;
  }
  message.textContent = "Đang đổi mật khẩu…";
  try {
    const response = await fetch("/api/account/password", {
      method: "POST",
      headers: apiHeaders(true),
      body: JSON.stringify({
        current_password: form.elements.current_password.value,
        new_password: form.elements.new_password.value
      })
    });
    const data = await parseResponse(response);
    alert(data.message);
    await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
    sessionStorage.removeItem("ztas_admin_token");
    location.replace("/login");
  } catch (error) {
    message.textContent = error.message;
  }
});

function openDocumentPermissionDialog(username) {
  userForDocumentPermissions = managedUsers.find(user => user.username === username) ?? null;
  if (!userForDocumentPermissions) return;
  const form = document.querySelector("#document-permission-form");
  const maximumLevel = maximumDocumentLevel(userForDocumentPermissions.role);
  const scope = scopeForTasks(userForDocumentPermissions.assigned_tasks);
  document.querySelector("#document-permission-user-label").textContent =
    `${userForDocumentPermissions.username} · ${roleLabel(userForDocumentPermissions.role)} · ${organizationLabel(userForDocumentPermissions.organization_unit)}`;
  document.querySelector("#document-permission-role-note").innerHTML =
    `<strong>Giới hạn theo vai trò: ${escapeHtml(rolePermissionShort(userForDocumentPermissions.role))}</strong><span>Admin chỉ có thể cấp tối đa Cấp ${maximumLevel} cho tài khoản này. Thiết bị, đơn vị và MFA vẫn được policy kiểm tra khi đọc.</span>`;
  [...form.elements.document_scope.options].forEach(option => {
    option.disabled = option.value !== "auto" && scopeLevel(option.value) > maximumLevel;
  });
  form.elements.document_scope.value = scopeLevel(scope) <= maximumLevel ? scope : "auto";
  form.elements.task_description.value = userForDocumentPermissions.task_description ?? "";
  document.querySelector("#document-permission-message").textContent = "";
  showDialog("document-permission-dialog");
}

document.querySelector("#document-permission-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!userForDocumentPermissions) return;
  const form = event.currentTarget;
  const message = document.querySelector("#document-permission-message");
  message.textContent = "Đang lưu quyền tài liệu…";
  try {
    const scope = form.elements.document_scope.value;
    const response = await fetch("/api/users/document-permissions", {
      method: "PUT",
      headers: apiHeaders(true),
      body: JSON.stringify({
        username: userForDocumentPermissions.username,
        assigned_tasks: tasksForScope(scope, userForDocumentPermissions.organization_unit),
        task_description: form.elements.task_description.value.trim()
      })
    });
    const data = await parseResponse(response);
    closeDialog("document-permission-dialog");
    userForDocumentPermissions = null;
    await refreshUsers();
    alert(data.message);
  } catch (error) {
    message.textContent = error.message;
  }
});

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
    const usernameField = form.querySelector('[name="username"]');
    const roleField = form.querySelector('[name="role"]');
    const organizationField = form.querySelector('[name="organization_unit"]');
    const scopeField = form.querySelector('[name="document_scope"]');
    const descriptionField = form.querySelector('[name="task_description"]');
    if (!usernameField || !roleField || !organizationField || !scopeField || !descriptionField) {
      throw new Error("Giao diện tạo tài khoản chưa được cập nhật đầy đủ. Hãy tải lại trang rồi thử lại.");
    }
    const organizationUnit = organizationField.value;
    const tasks = tasksForScope(scopeField.value, organizationUnit);
    const response = await fetch("/api/users", { method: "POST", headers: apiHeaders(true), body: JSON.stringify({ username: usernameField.value.trim(), role: roleField.value, organization_unit: organizationUnit, assigned_tasks: tasks, task_description: descriptionField.value.trim() }) });
    const data = await parseResponse(response);
    closeDialog("create-user-dialog");
    await refreshUsers();
    showAccountKey(data.user.username, data.account_key);
  } catch (error) { message.textContent = error.message; }
});

async function issueAccountKey(username) {
  if (!window.confirm(`Cấp lại Account Key cho ${username}? Key cũ sẽ mất hiệu lực ngay.`)) return;
  try {
    const response = await fetch(`/api/users/${encodeURIComponent(username)}/account-key`, {
      method: "POST", headers: apiHeaders()
    });
    const data = await parseResponse(response);
    showAccountKey(data.username, data.account_key, true);
  } catch (error) { alert(error.message); }
}

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
document.querySelector("#copy-account-key").addEventListener("click", async () => {
  if (!issuedAccountKey) return;
  await navigator.clipboard.writeText(issuedAccountKey);
  document.querySelector("#copy-account-key").textContent = "Đã sao chép";
});
document.querySelector("#account-key-result-dialog").addEventListener("close", () => {
  issuedAccountKey = "";
  document.querySelector("#issued-account-key").value = "";
  document.querySelector("#copy-account-key").textContent = "Sao chép key";
});
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
