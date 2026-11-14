const sessionLabel = document.querySelector("#reader-session");
const connection = document.querySelector("#connection-status");
const viewerTitle = document.querySelector("#viewer-title");
const viewerContent = document.querySelector("#viewer-content");
const decisionBadge = document.querySelector("#decision-badge");
const accountNote = document.querySelector("#reader-account-note");
const readerDialog = document.querySelector("#document-reader-dialog");
const readerDialogTitle = document.querySelector("#document-reader-title");
const readerDialogContent = document.querySelector("#document-reader-dialog-content");
const mfaCodeDialog = document.querySelector("#mfa-code-dialog");
let mfaCodeResolver = null;

let token = sessionStorage.getItem("ztas_document_token") || "";
let context = JSON.parse(sessionStorage.getItem("ztas_document_context") || "null");
let signedInAccount = context ? { username: context.username } : null;
let adminStorageLoaded = false;

const labels = {
  public: "Công khai", internal: "Nội bộ", confidential: "Mật / nhạy cảm",
  secret: "Bí mật", restricted: "Hạn chế đặc biệt"
};

const roleDocumentLevel = {
  guest: 1,
  employee: 2,
  manager: 3,
  engineer: 4,
  admin: 5
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'\"]/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  }[character]));
}

function setDecision(effect, text) {
  decisionBadge.className = "decision-badge";
  if (effect === "PERMIT") decisionBadge.classList.add("decision-badge--permit");
  if (effect === "DENY") decisionBadge.classList.add("decision-badge--deny");
  if (effect === "STEP_UP") decisionBadge.classList.add("decision-badge--step");
  decisionBadge.textContent = text || effect || "CHỜ";
}

function updateVisibleDocumentLevels() {
  const role = context?.role || signedInAccount?.role || "";
  const maximumLevel = roleDocumentLevel[role] || 0;
  const levels = document.querySelectorAll(".document-card[data-level]");
  let visibleCount = 0;
  levels.forEach(card => {
    const visible = Number(card.dataset.level) <= maximumLevel;
    card.hidden = !visible;
    if (visible) visibleCount += 1;
  });
  document.querySelector("#document-levels").style.setProperty(
    "--visible-level-count", String(Math.max(visibleCount, 1))
  );
}

function isAdminSession() {
  return (context?.role || signedInAccount?.role) === "admin";
}

function renderAdminDataZones(zones) {
  const container = document.querySelector("#document-zone-list");
  if (!zones.length) {
    container.innerHTML = "<p>Chưa có phân vùng dữ liệu.</p>";
    return;
  }
  container.innerHTML = `<table class="document-zone-table"><thead><tr><th>Phân vùng</th><th>Độ nhạy cảm</th><th>Tệp đã nạp</th><th>Thư mục lưu</th><th>Mô tả</th></tr></thead><tbody>${zones.map(zone => `<tr><td><strong>${escapeHtml(zone.name)}</strong><span class="document-zone-id">${escapeHtml(zone.id)}</span></td><td><span class="document-sensitivity">${escapeHtml(zone.sensitivity)}</span></td><td>${escapeHtml(zone.document_count)}</td><td class="document-zone-path">${escapeHtml(zone.storage_path)}</td><td class="document-zone-description">${escapeHtml(zone.description)}</td></tr>`).join("")}</tbody></table>`;
}

async function refreshAdminStorage() {
  const panel = document.querySelector("#document-admin-storage");
  if (!isAdminSession()) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  const container = document.querySelector("#document-zone-list");
  try {
    const response = await fetch("/api/data-zones", { cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Không thể tải phân vùng dữ liệu");
    renderAdminDataZones(data.zones ?? []);
    adminStorageLoaded = true;
  } catch (error) {
    container.innerHTML = `<p>Không thể tải phân vùng: ${escapeHtml(error.message)}</p>`;
  }
}

function updateAdminStorageVisibility() {
  const panel = document.querySelector("#document-admin-storage");
  if (!isAdminSession()) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  if (!adminStorageLoaded) refreshAdminStorage();
}

function openReaderDialog(title, content) {
  readerDialogTitle.textContent = title;
  readerDialogContent.innerHTML = content;
  if (!readerDialog.open) readerDialog.showModal();
}

function updateSession() {
  const account = context?.username ? context : signedInAccount;
  const ready = Boolean(token && context);
  sessionLabel.textContent = account ? `Đã đăng nhập: ${account.username}` : "Chưa đăng nhập tài khoản";
  sessionLabel.classList.toggle("reader-session--ready", Boolean(account));
  connection.innerHTML = `<i class="status-dot"></i>${account ? "Tài khoản đã xác thực" : "Sẵn sàng"}`;
  if (account) {
    accountNote.innerHTML = ready
      ? `<strong>Đã dùng tài khoản ${escapeHtml(account.username)}</strong><span>Quyền đọc và danh sách tệp được áp dụng tự động theo policy.</span>`
      : `<strong>Đã đăng nhập: ${escapeHtml(account.username)}</strong><span>Đang chờ ZTAS nhận dạng thiết bị đã cấp phát.</span>`;
  } else {
    accountNote.innerHTML = "<strong>Phiên đăng nhập không còn hiệu lực</strong><span>Vui lòng đăng nhập lại tại màn hình hệ thống.</span>";
  }
  updateVisibleDocumentLevels();
  updateAdminStorageVisibility();
}

function applyReaderIdentity(data) {
  token = data.access_token;
  context = { username: data.subject.username, role: data.subject.role, ...data.reader_context };
  signedInAccount = data.subject;
  sessionStorage.setItem("ztas_document_token", token);
  sessionStorage.setItem("ztas_document_context", JSON.stringify(context));
  updateSession();
}

function requestHeaders() {
  if (!token || !context) throw new Error("ZTAS chưa nhận dạng được thiết bị đã cấp phát cho tài khoản này.");
  return {
    Authorization: `Bearer ${token}`,
    "X-Device-ID": context.device_id,
    "X-Location-ID": context.location_id,
    "X-ZTAS-Reader-Session": "1"
  };
}

async function readResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return { kind: "json", value: await response.json() };
  return { kind: "file", value: await response.blob(), contentType };
}

async function stepUp(data) {
  let code = "";
  if (data.mfa_status === "SESSION_CODE_ALREADY_USED") {
    throw new Error(data.message || "Mã Step-Up đã được dùng trong phiên này. Hãy đăng xuất để yêu cầu mã mới.");
  }
  if ("Notification" in window && Notification.permission === "default") {
    Notification.requestPermission().catch(() => undefined);
  }
  if (data.mfa_status === "PENDING_ADMIN_CODE") {
    code = await waitForAdminCode(data);
  } else {
    const hint = data.demo_code ? ` Mã demo: ${data.demo_code}` : "";
    code = await requestMfaCode(data.required_auth_level, `Cần xác thực bổ sung cấp ${data.required_auth_level}.${hint}`);
  }
  while (code) {
    const response = await fetch("/api/step-up", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_id: data.challenge_id, mfa_code: code })
    });
    const result = await response.json().catch(() => ({}));
    if (response.ok) {
      token = result.access_token;
      sessionStorage.setItem("ztas_document_token", token);
      return;
    }
    if (result.error === "MFA_DEVICE_LOCKED") {
      throw new Error("Thiết bị đã bị khóa do nhập sai mã MFA 3 lần. Chờ admin gỡ khóa, sau đó yêu cầu mã mới.");
    }
    if (Number.isInteger(result.remaining_attempts)) {
      code = await requestMfaCode(
        data.required_auth_level,
        `Mã không đúng. Còn ${result.remaining_attempts} lần thử trước khi thiết bị bị khóa.`
      );
      continue;
    }
    throw new Error(result.error || "Xác thực bổ sung không thành công");
  }
  throw new Error("Đã hủy xác thực bổ sung.");
}

async function waitForAdminCode(data) {
  viewerTitle.textContent = "Đang chờ quản trị viên cấp mã MFA";
  viewerContent.innerHTML = `<div class="document-message"><strong>Yêu cầu đã vào hàng chờ.</strong><span>Admin cần xem xét yêu cầu và cấp mã xác thực cấp ${escapeHtml(data.required_auth_level)}. Mã sẽ được admin cung cấp cho bạn qua kênh an toàn.</span></div>`;

  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    await new Promise(resolve => window.setTimeout(resolve, 2000));
    const response = await fetch(`/api/mfa-challenges/${encodeURIComponent(data.challenge_id)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const status = await response.json().catch(() => ({}));
    if (response.ok && status.status === "CODE_READY") {
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification("ZTAS", { body: "Quản trị viên đã cấp mã Step-Up cho yêu cầu của bạn." });
      }
      const code = await requestMfaCode(data.required_auth_level);
      if (!code) throw new Error("Đã hủy xác thực bổ sung.");
      return code;
    }
    if (response.ok && status.status === "USED") {
      throw new Error("Mã Step-Up đã được dùng trong phiên này. Hãy đăng xuất để yêu cầu mã mới.");
    }
    if (response.ok && status.status === "REVOKED") {
      throw new Error("Quản trị viên đã thu hồi mã Step-Up của yêu cầu này.");
    }
    if (response.status === 404) throw new Error("Yêu cầu MFA đã hết hạn hoặc bị thu hồi.");
  }
  throw new Error("Hết thời gian chờ admin cấp mã MFA.");
}

function requestMfaCode(requiredLevel, initialMessage = "") {
  return new Promise(resolve => {
    mfaCodeResolver = resolve;
    const form = document.querySelector("#mfa-code-form");
    form.reset();
    document.querySelector("#mfa-code-description").textContent =
      `Quản trị viên đã cấp mã cho yêu cầu xác thực cấp ${requiredLevel}.`;
    document.querySelector("#mfa-code-message").textContent = initialMessage;
    mfaCodeDialog.showModal();
    form.elements.mfa_code.focus();
  });
}

async function loadStoredDocuments(zone) {
  const list = document.querySelector("#stored-document-list");
  list.innerHTML = "<p>Đang kiểm tra danh sách tệp…</p>";
  try {
    if (!token || !context) await restoreDashboardLogin();
    let response = await fetch(`/api/document-files/${encodeURIComponent(zone)}`, { headers: requestHeaders() });
    // Reader token co thoi han ngan, con cookie dang nhap he thong van hop le.
    // Tu cap lai token mot lan thay vi hien loi UNAUTHENTICATED cho nguoi dung.
    if (response.status === 401 && await restoreDashboardLogin()) {
      response = await fetch(`/api/document-files/${encodeURIComponent(zone)}`, { headers: requestHeaders() });
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok && data.effect === "STEP_UP") {
      setDecision("STEP_UP", "CẦN MFA");
      await stepUp(data);
      return loadStoredDocuments(zone);
    }
    if (!response.ok) throw new Error(data.reason_code || data.error || "Không thể tải danh sách tệp");
    viewerTitle.textContent = `Tệp trong vùng ${labels[zone]}`;
    viewerContent.innerHTML = "<p>Đã được cấp quyền. Chọn một tệp bên dưới để mở cửa sổ đọc.</p>";
    setDecision("PERMIT", "ĐƯỢC PHÉP");
    if (!data.files?.length) {
      list.innerHTML = "<p>Phân vùng này chưa có tệp do quản trị viên nạp.</p>";
      return;
    }
    list.innerHTML = data.files.map(file => `<button class="stored-document-button" type="button" data-zone="${escapeHtml(zone)}" data-filename="${escapeHtml(file.name)}"><strong>${escapeHtml(file.name)}</strong><small>${Number(file.size || 0).toLocaleString("vi-VN")} byte · Bấm để xem</small></button>`).join("");
    list.querySelectorAll(".stored-document-button").forEach(button => button.addEventListener("click", () => {
      const filename = button.dataset.filename;
      openDocument(`/documents/${encodeURIComponent(zone)}/${encodeURIComponent(filename)}`, filename);
    }));
  } catch (error) {
    viewerTitle.textContent = `Tài liệu ${labels[zone] || "được bảo vệ"}`;
    viewerContent.innerHTML = `<div class="document-message document-message--deny"><strong>Không thể mở phân vùng</strong><span>${escapeHtml(error.message)}</span></div>`;
    setDecision("DENY", "TỪ CHỐI");
    list.innerHTML = `<p>Không thể hiển thị danh sách: ${escapeHtml(error.message)}</p>`;
  }
}

async function openDocument(url, title, zone = "") {
  viewerTitle.textContent = title;
  viewerContent.innerHTML = "<p>Đang xin quyết định từ policy engine…</p>";
  setDecision("", "ĐANG KIỂM TRA");
  try {
    if (!token || !context) await restoreDashboardLogin();
    let response = await fetch(url, { headers: requestHeaders() });
    if (response.status === 401 && await restoreDashboardLogin()) {
      response = await fetch(url, { headers: requestHeaders() });
    }
    const parsed = await readResponse(response);
    if (!response.ok) {
      const data = parsed.kind === "json" ? parsed.value : {};
      if (data.effect === "STEP_UP") {
        setDecision("STEP_UP", "CẦN MFA");
        await stepUp(data);
        return openDocument(url, title);
      }
      setDecision("DENY", "TỪ CHỐI");
      viewerContent.innerHTML = `<div class="document-message document-message--deny"><strong>${escapeHtml(data.reason_code || data.error || "Không được cấp quyền")}</strong><span>${escapeHtml(data.message || "Policy không cho phép đọc tài liệu này với ngữ cảnh hiện tại.")}</span></div>`;
      return;
    }
    setDecision("PERMIT", "ĐƯỢC PHÉP");
    if (parsed.kind === "json") {
      viewerTitle.textContent = parsed.value.title || title;
      const content = `<article class="document-text">${escapeHtml(parsed.value.content || "Tài liệu không có nội dung.")}</article>`;
      viewerContent.innerHTML = `<p>Tài liệu đang được mở trong cửa sổ đọc.</p>`;
      openReaderDialog(parsed.value.title || title, content);
      if (zone) loadStoredDocuments(zone);
      return;
    }
    const objectUrl = URL.createObjectURL(parsed.value);
    if (parsed.contentType.includes("pdf") || parsed.contentType.startsWith("image/")) {
      const tag = parsed.contentType.includes("pdf") ? "iframe" : "img";
      const content = `<${tag} class="document-preview" src="${objectUrl}" title="${escapeHtml(title)}"></${tag}><a class="document-download" href="${objectUrl}" download> Tải tệp đã được cấp quyền</a>`;
      viewerContent.innerHTML = "<p>Tài liệu đang được mở trong cửa sổ đọc.</p>";
      openReaderDialog(title, content);
    } else if (parsed.contentType.startsWith("text/")) {
      const content = `<article class="document-text">${escapeHtml(await parsed.value.text())}</article>`;
      viewerContent.innerHTML = "<p>Tài liệu đang được mở trong cửa sổ đọc.</p>";
      openReaderDialog(title, content);
    } else {
      const content = `<div class="document-message"><strong>Tệp đã được cấp quyền.</strong><a class="document-download" href="${objectUrl}" download>Tải tệp về</a></div>`;
      viewerContent.innerHTML = "<p>Tệp đang được mở trong cửa sổ đọc.</p>";
      openReaderDialog(title, content);
    }
  } catch (error) {
    setDecision("DENY", "KHÔNG THỂ ĐỌC");
    viewerContent.innerHTML = `<div class="document-message document-message--deny"><strong>Không thể mở tài liệu</strong><span>${escapeHtml(error.message)}</span></div>`;
  }
}

document.querySelectorAll("[data-zone]").forEach(button => button.addEventListener("click", () => {
  const zone = button.dataset.zone;
  // Chọn cấp chỉ kiểm tra policy và tải danh sách tệp. Cửa sổ đọc nổi chỉ
  // xuất hiện khi người dùng bấm vào một tệp cụ thể trong danh sách.
  loadStoredDocuments(zone);
}));

document.querySelector("#document-reader-close").addEventListener("click", () => readerDialog.close());

document.querySelector("#document-upload-button").addEventListener("click", () => {
  if (!isAdminSession()) return;
  const form = document.querySelector("#document-upload-form");
  form.reset();
  document.querySelector("#document-upload-message").textContent = "";
  document.querySelector("#document-upload-dialog").showModal();
});

function closeUploadDialog() {
  document.querySelector("#document-upload-dialog").close();
}

document.querySelector("#document-upload-close").addEventListener("click", closeUploadDialog);
document.querySelector("#document-upload-cancel").addEventListener("click", closeUploadDialog);

document.querySelector("#document-upload-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!isAdminSession()) return;
  const form = event.currentTarget;
  const message = document.querySelector("#document-upload-message");
  const file = form.elements.document.files[0];
  if (!file) return;
  if (file.size > 25 * 1024 * 1024) {
    message.textContent = "Tệp vượt giới hạn 25 MB.";
    return;
  }
  message.textContent = "Đang tải tài liệu lên…";
  try {
    const response = await fetch("/api/data-zones/upload", {
      method: "POST",
      body: new FormData(form)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Tải tài liệu thất bại");
    adminStorageLoaded = false;
    closeUploadDialog();
    await refreshAdminStorage();
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  sessionStorage.removeItem("ztas_document_token");
  sessionStorage.removeItem("ztas_document_context");
  token = ""; context = null; signedInAccount = null; updateSession();
  await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
  viewerTitle.textContent = "Chọn mức tài liệu để đọc";
  viewerContent.innerHTML = "<p>Đã đăng xuất tài khoản.</p>";
  setDecision("", "CHỜ");
});

document.querySelector("#mfa-code-form").addEventListener("submit", event => {
  event.preventDefault();
  const code = event.currentTarget.elements.mfa_code.value;
  const resolve = mfaCodeResolver;
  mfaCodeResolver = null;
  mfaCodeDialog.close();
  resolve?.(code);
});
document.querySelector("#mfa-code-close").addEventListener("click", () => mfaCodeDialog.close());
document.querySelector("#mfa-code-cancel").addEventListener("click", () => mfaCodeDialog.close());
mfaCodeDialog.addEventListener("close", () => {
  const resolve = mfaCodeResolver;
  mfaCodeResolver = null;
  resolve?.("");
});

updateSession();

async function restoreDashboardLogin() {
  try {
    const meResponse = await fetch("/api/me");
    const account = await meResponse.json().catch(() => null);
    if (!meResponse.ok || !account?.username) return false;

    // Cookie HttpOnly cua Dashboard xac nhan admin da dang nhap, vi vay tuyet
    // doi khong hien lai form username/password tren menu Tai lieu.
    signedInAccount = account;
    updateSession();

    const contextResponse = await fetch("/api/reader-context");
    const data = await contextResponse.json().catch(() => ({}));
    if (contextResponse.ok && data?.access_token && data?.reader_context) {
      applyReaderIdentity(data);
      return true;
    }

    viewerTitle.textContent = "Thiết bị chưa được nhận dạng";
    viewerContent.innerHTML = `<div class="document-message document-message--deny"><strong>Chưa thể đọc tài liệu</strong><span>${escapeHtml(data.message || "Quản trị viên cần cấp phát hoặc phê duyệt thiết bị/IP hiện tại trước khi đọc tài liệu.")}</span></div>`;
    setDecision("DENY", "CHỜ THIẾT BỊ");
    return false;
  } catch (_) {
    return false;
  }
}

// Luon cap lai token doc tu cookie dang nhap he thong khi mo trang. Cach nay
// tranh sessionStorage con token cu sau khi server hoac OPA da khoi dong lai.
restoreDashboardLogin();
