const sessionLabel = document.querySelector("#reader-session");
const connection = document.querySelector("#connection-status");
const viewerTitle = document.querySelector("#viewer-title");
const viewerContent = document.querySelector("#viewer-content");
const decisionBadge = document.querySelector("#decision-badge");
const accountNote = document.querySelector("#reader-account-note");
const readerDialog = document.querySelector("#document-reader-dialog");
const readerDialogTitle = document.querySelector("#document-reader-title");
const readerDialogContent = document.querySelector("#document-reader-dialog-content");

let token = sessionStorage.getItem("ztas_document_token") || "";
let context = JSON.parse(sessionStorage.getItem("ztas_document_context") || "null");
let signedInAccount = context ? { username: context.username } : null;

const labels = {
  public: "Công khai", internal: "Nội bộ", confidential: "Mật / nhạy cảm",
  secret: "Bí mật", restricted: "Hạn chế đặc biệt"
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
}

function applyReaderIdentity(data) {
  token = data.access_token;
  context = { username: data.subject.username, ...data.reader_context };
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
  const hint = data.demo_code ? ` Mã demo: ${data.demo_code}` : "";
  const code = window.prompt(`Cần xác thực bổ sung cấp ${data.required_auth_level}.${hint}`);
  if (!code) throw new Error("Đã hủy xác thực bổ sung.");
  const response = await fetch("/api/step-up", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ challenge_id: data.challenge_id, mfa_code: code })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "Xác thực bổ sung không thành công");
  token = result.access_token;
  sessionStorage.setItem("ztas_document_token", token);
}

async function loadStoredDocuments(zone) {
  const list = document.querySelector("#stored-document-list");
  list.innerHTML = "<p>Đang kiểm tra danh sách tệp…</p>";
  try {
    const response = await fetch(`/api/document-files/${encodeURIComponent(zone)}`, { headers: requestHeaders() });
    const data = await response.json().catch(() => ({}));
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
    const response = await fetch(url, { headers: requestHeaders() });
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

document.querySelector("#logout-button").addEventListener("click", async () => {
  sessionStorage.removeItem("ztas_document_token");
  sessionStorage.removeItem("ztas_document_context");
  token = ""; context = null; signedInAccount = null; updateSession();
  await fetch("/api/logout", { method: "POST" }).catch(() => undefined);
  viewerTitle.textContent = "Chọn mức tài liệu để đọc";
  viewerContent.innerHTML = "<p>Đã đăng xuất tài khoản.</p>";
  setDecision("", "CHỜ");
});

updateSession();

async function restoreDashboardLogin() {
  try {
    const meResponse = await fetch("/api/me");
    const account = await meResponse.json().catch(() => null);
    if (!meResponse.ok || !account?.username) return;

    // Cookie HttpOnly cua Dashboard xac nhan admin da dang nhap, vi vay tuyet
    // doi khong hien lai form username/password tren menu Tai lieu.
    signedInAccount = account;
    updateSession();

    const contextResponse = await fetch("/api/reader-context");
    const data = await contextResponse.json().catch(() => ({}));
    if (contextResponse.ok && data?.access_token && data?.reader_context) {
      applyReaderIdentity(data);
      return;
    }

    viewerTitle.textContent = "Thiết bị chưa được nhận dạng";
    viewerContent.innerHTML = `<div class="document-message document-message--deny"><strong>Chưa thể đọc tài liệu</strong><span>${escapeHtml(data.message || "Quản trị viên cần cấp phát hoặc phê duyệt thiết bị/IP hiện tại trước khi đọc tài liệu.")}</span></div>`;
    setDecision("DENY", "CHỜ THIẾT BỊ");
  } catch (_) {}
}

if (!token || !context) restoreDashboardLogin();
