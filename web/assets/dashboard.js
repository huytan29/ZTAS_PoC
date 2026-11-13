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
const enrollmentProfiles = {
  guest: { trust: 1, location: "external-network" },
  unmanaged: { trust: 2, location: "external-network" },
  "managed-vm": { trust: 3, location: "lab-network" },
  trusted: { trust: 4, location: "campus-network" },
  secure: { trust: 5, location: "secure-zone" }
};
let adminToken = sessionStorage.getItem("ztas_admin_token") ?? "";
let pendingAdminAction = null;
let deviceToRevoke = null;
let deviceToDelete = null;
let issuedCredential = null;
let assignableUsers = [];
let weatherLoading = false;
let deviceViewSignature = "";
let deviceTableScrollLeft = 0;
let deviceTableInteractionUntil = 0;
let selectedMfaChallengeId = "";

const weatherArt = {
  clear: '<svg class="weather-graphic weather-graphic--clear" viewBox="0 0 48 48" role="img"><circle class="weather-sun" cx="24" cy="24" r="10" fill="#f6b73c"/><g class="weather-rays" stroke="#f6b73c" stroke-width="3" stroke-linecap="round"><path d="M24 4v5M24 39v5M4 24h5M39 24h5M10 10l4 4M34 34l4 4M38 10l-4 4M14 34l-4 4"/></g></svg>',
  cloudy: '<svg class="weather-graphic weather-graphic--cloudy" viewBox="0 0 48 48" role="img"><circle class="weather-cloud-sun" cx="18" cy="16" r="7" fill="#f6c453"/><path class="weather-cloud" d="M14 37h23a8 8 0 0 0 0-16 11 11 0 0 0-21-2 9 9 0 0 0-2 18Z" fill="#9eafc4"/></svg>',
  rain: '<svg class="weather-graphic weather-graphic--rain" viewBox="0 0 48 48" role="img"><path class="weather-cloud" d="M10 29h27a8 8 0 0 0 0-16 11 11 0 0 0-21-2 9 9 0 0 0-6 18Z" fill="#879db7"/><g class="weather-rain" stroke="#4b8fe2" stroke-width="3" stroke-linecap="round"><path d="m16 34-2 6m10-6-2 6m10-6-2 6"/></g></svg>',
  calm: '<svg class="weather-graphic weather-graphic--calm" viewBox="0 0 48 48" role="img"><path class="weather-cloud" d="M10 30h27a8 8 0 0 0 0-16 11 11 0 0 0-21-2 9 9 0 0 0-6 18Z" fill="#a9b6c6"/><path class="weather-breeze" d="M12 38h17m-10 4h17" stroke="#8696a9" stroke-width="2.5" stroke-linecap="round"/></svg>'
};

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
  const element = document.querySelector(id);
  if (element) element.textContent = value;
}

function weatherDescriptor(code) {
  if (code === 0) return { label: "Trời nắng", art: "clear" };
  if ([1, 2, 3].includes(code)) return { label: "Trời râm", art: "cloudy" };
  if ([45, 48].includes(code)) return { label: "Sương mù", art: "calm" };
  if ((code >= 51 && code <= 67) || (code >= 80 && code <= 82) || code >= 95) {
    return { label: code >= 95 ? "Mưa dông" : "Trời mưa", art: "rain" };
  }
  return { label: "Thời tiết bình thường", art: "calm" };
}

function updateLocalDateTime() {
  const now = new Date();
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "Múi giờ cục bộ";
  updateText("#local-date-time", now.toLocaleString("vi-VN", {
    weekday: "short", day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  }));
  updateText("#local-time-zone", `Vùng giờ: ${zone}`);
  if (!document.querySelector("#weather-illustration").innerHTML) {
    document.querySelector("#weather-illustration").innerHTML = weatherArt.calm;
  }
}

async function loadWeatherForCurrentPosition() {
  const button = document.querySelector("#weather-location-button");
  const location = document.querySelector("#weather-location");
  const condition = document.querySelector("#weather-condition");
  if (weatherLoading) return;
  if (!navigator.geolocation) {
    location.textContent = "Trình duyệt không hỗ trợ lấy vị trí";
    return;
  }

  weatherLoading = true;
  button.disabled = true;
  button.textContent = "Đang xác định…";
  navigator.geolocation.getCurrentPosition(async position => {
    const { latitude, longitude } = position.coords;
    try {
      const url = new URL("https://api.open-meteo.com/v1/forecast");
      url.search = new URLSearchParams({
        latitude: String(latitude), longitude: String(longitude),
        current: "temperature_2m,apparent_temperature,weather_code",
        timezone: "auto"
      }).toString();
      const addressUrl = new URL("https://nominatim.openstreetmap.org/reverse");
      addressUrl.search = new URLSearchParams({
        lat: String(latitude), lon: String(longitude), format: "jsonv2",
        zoom: "10", addressdetails: "1", "accept-language": "vi"
      }).toString();
      const [response, addressResponse] = await Promise.all([
        fetch(url),
        fetch(addressUrl).catch(() => null)
      ]);
      if (!response.ok) throw new Error("WEATHER_SERVICE_UNAVAILABLE");
      const data = await response.json();
      const weather = data.current;
      if (!weather) throw new Error("WEATHER_DATA_MISSING");
      const descriptor = weatherDescriptor(weather.weather_code);
      document.querySelector("#weather-illustration").innerHTML = weatherArt[descriptor.art];
      condition.textContent = `${descriptor.label} · ${Math.round(weather.temperature_2m)}°C`;
      let geographicAddress = "Khu vực hiện tại";
      if (addressResponse?.ok) {
        const addressData = await addressResponse.json();
        const address = addressData.address ?? {};
        const parts = [
          address.city ?? address.town ?? address.village ?? address.municipality,
          address.state_district ?? address.state,
          address.country
        ].filter((part, index, values) => part && values.indexOf(part) === index);
        geographicAddress = parts.join(", ") || addressData.display_name || geographicAddress;
      }
      location.textContent = geographicAddress;
      location.title = `${latitude.toFixed(4)}°, ${longitude.toFixed(4)}°`;
      if (data.timezone) updateText("#local-time-zone", `Vùng giờ: ${data.timezone}`);
      button.textContent = "Làm mới";
    } catch {
      condition.textContent = "Không lấy được thời tiết";
      location.textContent = "Không thể kết nối dịch vụ thời tiết";
      button.textContent = "Thử lại";
    } finally {
      weatherLoading = false;
      button.disabled = false;
    }
  }, () => {
    weatherLoading = false;
    location.textContent = "Chưa thể lấy vị trí tự động — hãy cho phép quyền Vị trí trong trình duyệt";
    button.disabled = false;
    button.textContent = "Thử lại";
  }, { enableHighAccuracy: false, timeout: 10000, maximumAge: 15 * 60 * 1000 });
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
          <td data-label="Thiết bị" class="device-table__device"><i class="status-dot status-dot--${dotClass}"></i><strong>${escapeHtml(device.device_name || device.id)}</strong><span class="device-table__id">${escapeHtml(device.id)} · ${escapeHtml(device.device_type || "unknown")}</span></td>
          <td data-label="Trạng thái Zero Trust"><span class="device-status device-status--${info.cardClass}">${info.label}</span></td>
          <td data-label="Vùng mạng"><span class="device-zone">${escapeHtml(device.location_id)}</span></td>
          <td data-label="Độ tin cậy"><span class="trust-value">${escapeHtml(device.trust_level)}/5</span></td>
          <td data-label="Tài khoản được gán" class="device-table__accounts">${assignedAccounts(device)}</td>
          <td data-label="Hoạt động gần nhất" class="device-table__activity"><strong>${lastActivity(device)}</strong><span>${formatTime(device.last_seen)}</span></td>
          <td data-label="Thao tác" class="device-table__actions">
            ${device.registered
              ? `<button class="button button--secondary button--small" data-update-device-ip="${escapeHtml(device.id)}">Cập nhật IP</button><button class="button button--secondary button--small" data-revoke-device="${escapeHtml(device.id)}">Thu hồi</button><button class="button button--danger-outline button--small" data-block-device="${escapeHtml(device.id)}">Chặn</button>`
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

  const tableWrap = container.querySelector(".device-table-wrap");
  if (tableWrap) {
    // Việc dựng lại bảng sau khi dữ liệu đổi không được làm người dùng mất vị
    // trí đang kéo ngang. Đặt lại sau hai khung hình để trình duyệt hoàn tất
    // tính kích thước bảng trước.
    const restoreScroll = () => { tableWrap.scrollLeft = deviceTableScrollLeft; };
    requestAnimationFrame(() => requestAnimationFrame(restoreScroll));

    const markInteraction = () => {
      deviceTableInteractionUntil = Date.now() + 1800;
    };
    tableWrap.addEventListener("scroll", () => {
      deviceTableScrollLeft = tableWrap.scrollLeft;
      markInteraction();
    }, { passive: true });
    ["pointerdown", "pointermove", "touchstart", "wheel"].forEach(eventName => {
      tableWrap.addEventListener(eventName, markInteraction, { passive: true });
    });
  }

  container.querySelectorAll("[data-revoke-device]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openRevokeDialog(button.dataset.revokeDevice));
    });
  });

  container.querySelectorAll("[data-update-device-ip]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => updateDeviceIp(button.dataset.updateDeviceIp));
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

  container.querySelectorAll("[data-block-device]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => blockDevice(button.dataset.blockDevice));
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
      <thead><tr><th>Thiết bị yêu cầu</th><th>Profile / tài khoản</th><th>Vùng mạng</th><th>IP nguồn</th><th>Lần đầu / gần nhất</th><th>Thông tin máy khách</th><th>Thao tác</th></tr></thead>
      <tbody>${requests.map(request => `
        <tr>
          <td><strong>${escapeHtml(request.device_name || request.device_id)}</strong><span class="request-state"><i class="status-dot status-dot--warning"></i>${request.enrollment_profile === "account-key" ? "Tài khoản + Account Key hợp lệ · chờ duyệt" : request.enrollment_verified ? "Thông tin đăng ký hợp lệ · chờ duyệt" : "Chờ phân loại"}</span><span class="request-id">${escapeHtml(request.device_id)} · ${escapeHtml(request.device_type || "unknown")}</span></td>
          <td><strong>${escapeHtml(request.enrollment_profile || "manual")}</strong><span class="request-account">${escapeHtml(request.requested_username || "Chưa gán tài khoản")}</span></td>
          <td><span class="device-zone">${escapeHtml(request.location_id)}</span></td>
          <td><span class="device-zone">${escapeHtml(request.source_ip)}</span></td>
          <td class="request-time"><strong>${formatTime(request.first_seen)}</strong><span>Cập nhật: ${formatTime(request.last_seen)}</span></td>
          <td class="request-agent" title="${escapeHtml(request.user_agent)}">${escapeHtml(request.user_agent)}</td>
          <td><button class="button button--primary button--small" data-approve-request="${escapeHtml(request.device_id)}" data-request-location="${escapeHtml(request.location_id)}" data-request-profile="${escapeHtml(request.enrollment_profile || "manual")}" data-request-user="${escapeHtml(request.requested_username || "")}" data-request-name="${escapeHtml(request.device_name || request.device_id)}" data-request-type="${escapeHtml(request.device_type || "unknown")}" data-request-ip="${escapeHtml(request.source_ip || "")}">Phân loại &amp; cấp quyền</button></td>
        </tr>`).join("")}</tbody>
    </table>`;

  container.querySelectorAll("[data-approve-request]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openEnrollDialog(
        button.dataset.approveRequest,
        button.dataset.requestLocation,
        button.dataset.requestProfile,
        button.dataset.requestUser,
        button.dataset.requestName,
        button.dataset.requestType,
        button.dataset.requestIp
      ));
    });
  });
}

function renderMfaRequests(requests, lockedDevices = []) {
  const container = document.querySelector("#mfa-request-list");
  const count = document.querySelector("#pending-mfa-request-count");
  const pending = requests.filter(request => !request.code_ready && !request.code_revoked);
  count.textContent = `${pending.length} yêu cầu chờ`;

  if (!requests.length && !lockedDevices.length) {
    container.innerHTML = '<p class="empty-state">Không có yêu cầu MFA đang chờ xử lý.</p>';
    return;
  }

  container.innerHTML = `
    <table class="connection-request-table">
      <thead><tr><th>Người dùng / thiết bị</th><th>Tài nguyên yêu cầu</th><th>Mức MFA</th><th>Thời điểm yêu cầu</th><th>Trạng thái</th><th>Thao tác admin</th></tr></thead>
      <tbody>${lockedDevices.map(device => `
        <tr>
          <td><strong>${escapeHtml(device.username || "Không xác định")}</strong><span class="request-account">Thiết bị ${escapeHtml(device.device_id)}</span></td>
          <td><span class="device-zone">Khóa do nhập sai mã</span></td>
          <td><span class="trust-value">${escapeHtml(device.failed_attempts)}/3 lần sai</span></td>
          <td class="request-time"><strong>${formatTime(device.locked_at)}</strong><span>Chờ admin gỡ khóa</span></td>
          <td><span class="device-status device-status--unidentified">Thiết bị bị khóa</span></td>
          <td><button class="button button--primary button--small" data-unlock-mfa-device="${escapeHtml(device.device_id)}">Gỡ khóa</button></td>
        </tr>`).join("")}${requests.map(request => `
        <tr>
          <td><strong>${escapeHtml(request.username)}</strong><span class="request-account">${escapeHtml(request.role)} · ${escapeHtml(request.device_id)}</span></td>
          <td><span class="device-zone">${escapeHtml(request.resource_id)}</span></td>
          <td><span class="trust-value">Cấp ${escapeHtml(request.required_auth_level)}</span></td>
          <td class="request-time"><strong>${formatTime(request.requested_at)}</strong><span>Hết hạn: ${formatTime(request.expires_at)}</span></td>
          <td><span class="device-status device-status--${request.code_revoked ? "unidentified" : request.code_used ? "identified" : request.code_ready ? "identified" : "step-up"}">${request.code_revoked ? "Đã thu hồi" : request.code_used ? "Đã dùng trong phiên" : request.code_ready ? "Đã cấp mã" : "Chờ admin"}</span></td>
          <td>${request.code_revoked
            ? '<span class="account-empty">Quyền Step-Up đã bị chặn</span>'
            : request.code_used
            ? `<button class="button button--danger-outline button--small" data-revoke-mfa="${escapeHtml(request.challenge_id)}">Thu hồi MFA</button>`
            : request.code_ready
            ? `<button class="button button--danger-outline button--small" data-revoke-mfa="${escapeHtml(request.challenge_id)}">Thu hồi MFA</button>`
            : `<button class="button button--primary button--small" data-issue-mfa-code="${escapeHtml(request.challenge_id)}" data-mfa-user="${escapeHtml(request.username)}" data-mfa-resource="${escapeHtml(request.resource_id)}">Tạo mã</button>`}</td>
        </tr>`).join("")}</tbody>
    </table>`;

  container.querySelectorAll("[data-issue-mfa-code]").forEach(button => {
    button.addEventListener("click", () => {
      requireAdmin(() => openMfaCodeDialog(
        button.dataset.issueMfaCode,
        button.dataset.mfaUser,
        button.dataset.mfaResource
      ));
    });
  });
  container.querySelectorAll("[data-revoke-mfa]").forEach(button => {
    button.addEventListener("click", () => revokeMfaCode(button.dataset.revokeMfa));
  });
  container.querySelectorAll("[data-unlock-mfa-device]").forEach(button => {
    button.addEventListener("click", () => unlockMfaDevice(button.dataset.unlockMfaDevice));
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

  // Dashboard nhận dữ liệu mới mỗi giây. Không dựng lại cả bảng nếu thiết bị
  // chưa thay đổi, vì việc đó làm mất vị trí cuộn đang xem của người quản trị.
  const nextSignature = JSON.stringify(devices);
  if (nextSignature !== deviceViewSignature) {
    const previousTable = document.querySelector("#device-list .device-table-wrap");
    if (previousTable) deviceTableScrollLeft = previousTable.scrollLeft;

    // Trong khi kéo thanh cuộn, tạm hoãn render để thao tác không bị giật
    // hoặc tự quay về đầu do chu kỳ làm mới dữ liệu một giây.
    if (Date.now() < deviceTableInteractionUntil) return;

    renderDeviceCards(devices);
    deviceViewSignature = nextSignature;
  }
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
  } catch {
    setConnection(false);
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

async function refreshMfaRequests() {
  const container = document.querySelector("#mfa-request-list");
  const loginButton = document.querySelector("#mfa-admin-login-button");
  if (!adminToken) {
    loginButton.hidden = false;
    document.querySelector("#pending-mfa-request-count").textContent = "Chỉ admin";
    container.innerHTML = '<p class="empty-state">Đăng nhập admin để xem và cấp mã MFA.</p>';
    return;
  }
  loginButton.hidden = true;
  try {
    const response = await fetch("/api/mfa-requests", { headers: apiHeaders(), cache: "no-store" });
    const data = await parseResponse(response);
    renderMfaRequests(data.requests ?? [], data.locked_devices ?? []);
  } catch (error) {
    container.innerHTML = `<p class="empty-state">Không thể tải hàng chờ MFA: ${escapeHtml(error.message)}</p>`;
  }
}

async function refreshMacCaptureSettings() {
  const toggle = document.querySelector("#mac-capture-toggle");
  const state = document.querySelector("#mac-capture-state");
  if (!adminToken) {
    toggle.checked = false;
    state.textContent = "Chỉ admin";
    return;
  }

  try {
    const response = await fetch("/api/device-security-settings", {
      headers: apiHeaders(), cache: "no-store"
    });
    const settings = await parseResponse(response);
    toggle.checked = Boolean(settings.mac_capture_enabled);
    state.textContent = toggle.checked ? "Đang bật" : "Đang tắt";
  } catch {
    toggle.checked = false;
    state.textContent = "Không tải được";
  }
}

async function setMacCaptureEnabled(enabled) {
  const toggle = document.querySelector("#mac-capture-toggle");
  const state = document.querySelector("#mac-capture-state");
  toggle.disabled = true;
  state.textContent = "Đang lưu…";
  try {
    const response = await fetch("/api/device-security-settings", {
      method: "PUT",
      headers: apiHeaders(),
      body: JSON.stringify({ mac_capture_enabled: enabled })
    });
    const settings = await parseResponse(response);
    toggle.checked = Boolean(settings.mac_capture_enabled);
    state.textContent = toggle.checked ? "Đang bật" : "Đang tắt";
  } catch (error) {
    toggle.checked = !enabled;
    state.textContent = error.message;
  } finally {
    toggle.disabled = false;
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

function openMfaCodeDialog(challengeId, username, resourceId) {
  selectedMfaChallengeId = challengeId;
  const form = document.querySelector("#issue-mfa-code-form");
  form.reset();
  document.querySelector("#issue-mfa-code-context").textContent =
    `Cấp mã cho ${username} khi truy cập ${resourceId}. Admin có thể thu hồi mã hoặc quyền Step-Up bất cứ lúc nào.`;
  document.querySelector("#issue-mfa-code-message").textContent = "";
  showDialog("issue-mfa-code-dialog");
}

function validAdminMfaCode(code) {
  return code.length >= 6 && /[A-Z]/.test(code) && /[^A-Za-z0-9\s]/.test(code);
}

async function revokeMfaCode(challengeId) {
  if (!window.confirm("Thu hồi mã MFA và chặn ngay quyền Step-Up đang dùng?")) return;
  try {
    const response = await fetch(`/api/mfa-requests/${encodeURIComponent(challengeId)}`, {
      method: "DELETE", headers: apiHeaders()
    });
    await parseResponse(response);
    refreshMfaRequests();
  } catch (error) { alert(error.message); }
}

async function unlockMfaDevice(deviceId) {
  if (!window.confirm("Gỡ khóa thiết bị này? Mã MFA cũ sẽ bị hủy và người dùng phải yêu cầu mã mới.")) return;
  try {
    const response = await fetch(`/api/mfa-device-locks/${encodeURIComponent(deviceId)}/unlock`, {
      method: "POST", headers: apiHeaders()
    });
    await parseResponse(response);
    refreshMfaRequests();
  } catch (error) { alert(error.message); }
}

async function loadAssignableUsers(selector) {
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

function applyEnrollmentProfile(form, profileId) {
  const profile = enrollmentProfiles[profileId];
  if (!profile) return;
  form.elements.trust_level.value = String(profile.trust);
  form.elements.location_id.value = profile.location;
}

async function openEnrollDialog(
  deviceId = "",
  locationId = "lab-network",
  profileId = "managed-vm",
  assignedUsername = "",
  deviceName = "",
  deviceType = "unknown",
  allowedIpAddress = ""
) {
  const form = document.querySelector("#enroll-device-form");
  form.reset();
  form.elements.device_id.value = deviceId;
  form.elements.device_name.value = deviceName;
  form.elements.device_type.value = deviceType;
  form.elements.allowed_ip_address.value = allowedIpAddress;
  form.elements.enrollment_profile.value = enrollmentProfiles[profileId] ? profileId : "manual";
  if (enrollmentProfiles[profileId]) {
    applyEnrollmentProfile(form, profileId);
  } else {
    form.elements.trust_level.value = "3";
    form.elements.location_id.value = [...form.elements.location_id.options]
      .some(option => option.value === locationId) ? locationId : "lab-network";
  }
  document.querySelector("#enroll-device-message").textContent = "";
  await loadAssignableUsers(form.elements.assigned_username);
  if (assignedUsername && [...form.elements.assigned_username.options]
    .some(option => option.value === assignedUsername)) {
    form.elements.assigned_username.value = assignedUsername;
  }
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

async function blockDevice(deviceId) {
  if (!confirm(`Chặn ${deviceId}? Device Key sẽ bị vô hiệu hóa ngay.`)) return;
  try {
    const response = await fetch("/api/devices/block", {
      method: "POST",
      headers: apiHeaders(),
      body: JSON.stringify({ device_id: deviceId })
    });
    await parseResponse(response);
    refreshDashboard();
  } catch (error) {
    alert(error.message);
  }
}

async function updateDeviceIp(deviceId) {
  const allowedIpAddress = prompt(`Nhập IPv4 hoặc IPv6 được phép cho ${deviceId}:`);
  if (allowedIpAddress === null || !allowedIpAddress.trim()) return;
  try {
    const response = await fetch("/api/devices/network-identity", {
      method: "PUT",
      headers: apiHeaders(),
      body: JSON.stringify({
        device_id: deviceId,
        allowed_ip_address: allowedIpAddress.trim()
      })
    });
    const data = await parseResponse(response);
    alert(data.message);
    refreshDashboard();
  } catch (error) {
    alert(error.message);
  }
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

document.querySelector("#mfa-admin-login-button").addEventListener("click", () => {
  requireAdmin(() => refreshMfaRequests());
});

document.querySelector("#weather-location-button").addEventListener("click", () => {
  loadWeatherForCurrentPosition();
});

document.querySelector("#enroll-device-form select[name=enrollment_profile]").addEventListener("change", event => {
  applyEnrollmentProfile(document.querySelector("#enroll-device-form"), event.target.value);
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
    refreshMacCaptureSettings();
    refreshMfaRequests();
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
        device_name: form.elements.device_name.value.trim(),
        device_type: form.elements.device_type.value,
        enrollment_profile: form.elements.enrollment_profile.value,
        trust_level: Number(form.elements.trust_level.value),
        location_id: form.elements.location_id.value,
        allowed_ip_address: form.elements.allowed_ip_address.value.trim(),
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

document.querySelector("#mac-capture-toggle").addEventListener("change", event => {
  const desired = event.currentTarget.checked;
  if (!adminToken) {
    event.currentTarget.checked = !desired;
    requireAdmin(() => setMacCaptureEnabled(desired));
    return;
  }
  setMacCaptureEnabled(desired);
});

document.querySelector("#issue-mfa-code-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("#issue-mfa-code-message");
  const code = form.elements.code.value.trim();
  if (!validAdminMfaCode(code)) {
    message.textContent = "Mã cần tối thiểu 6 ký tự, 1 chữ hoa và 1 ký tự đặc biệt.";
    return;
  }
  message.textContent = "Đang cấp mã…";
  try {
    const response = await fetch(`/api/mfa-requests/${encodeURIComponent(selectedMfaChallengeId)}/code`, {
      method: "POST", headers: apiHeaders(), body: JSON.stringify({ code })
    });
    await parseResponse(response);
    closeDialog("issue-mfa-code-dialog");
    selectedMfaChallengeId = "";
    refreshMfaRequests();
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
refreshConnectionRequests();
refreshMfaRequests();
refreshMacCaptureSettings();
updateLocalDateTime();
loadWeatherForCurrentPosition();
setInterval(updateLocalDateTime, 1000);
setInterval(() => {
  refreshDashboard();
  refreshConnectionRequests();
  refreshMfaRequests();
  refreshMacCaptureSettings();
}, 1000);
