# ZTAS PoC

Hệ thống Zero Trust cho môi trường lab: xác thực tài khoản, kiểm tra thiết bị,
IP, trust, unit, task và MFA trước khi cho đọc hoặc nạp tài liệu.

| Server | Máy khách | URL |
| --- | --- | --- |
| Windows 10/11 hoặc macOS | Windows, Ubuntu/Linux, macOS | `https://ztas.ptit:8443` |

> Mỗi môi trường chỉ chạy **một server ZTAS**. Server chạy ZTAS, Docker OPA và
> Caddy. Máy khách chỉ nhận gói `Client_PoC`.

## Mục lục

1. [Triển khai Windows Server](#1-triển-khai-windows-server)
2. [Triển khai macOS Server](#2-triển-khai-macos-server)
3. [Thiết lập admin và tài khoản](#3-thiết-lập-admin-và-tài-khoản)
4. [Cấp phát máy khách](#4-cấp-phát-máy-khách)
5. [Vận hành và kiểm thử](#5-vận-hành-và-kiểm-thử)
6. [Xử lý sự cố](#6-xử-lý-sự-cố)

---

# 1. Triển khai Windows Server

## 1.1 Cài công cụ một lần

Mở **CMD bằng Run as administrator**. Cài Git for Windows, CMake **4.4.4+**,
MSYS2 MinGW-w64 x64 và Docker Desktop. Caddy không cần cài trước: lệnh deploy
tự tải Caddy vào `C:\Tools\Caddy` nếu chưa có.

Sau khi cài MSYS2, mở **MSYS2 MinGW x64** rồi chạy:

```bash
pacman -Syu
pacman -S --needed mingw-w64-x86_64-toolchain
```

Thêm đường dẫn sau vào PATH Windows, sau đó mở CMD mới:

```text
C:\msys64\mingw64\bin
```

Kiểm tra trong CMD:

```cmd
git --version
cmake --version
where g++
where mingw32-make
docker info
```

Nếu `docker info` lỗi, mở Docker Desktop và đợi **Engine running**.

## 1.2 Clone source

```cmd
cd /d E:\
git clone https://github.com/huytan29/ZTAS_PoC.git ZTAS_PoC
cd /d E:\ZTAS_PoC
```

## 1.3 Deploy HTTPS

Trong CMD Administrator:

```cmd
cd /d E:\ZTAS_PoC
set VCPKG_FORCE_SYSTEM_BINARIES=
mingw32-make deploy
```

Lệnh này tự động build, khởi động OPA/ZTAS/Caddy, mở Firewall TCP `8443` và UDP
`8021`, tạo Private CA, tạo gói `Client_PoC` và tự mở trang đăng nhập ZTAS.

Kết quả mong đợi:

```text
[DONE] Dashboard: https://ztas.ptit:8443/dashboard
[DONE] Tools cho may khach: E:\ZTAS_PoC\Client_PoC
```

Nếu server không tự nhận IP LAN, xem bằng `ipconfig`, sau đó dùng ví dụ:

```cmd
mingw32-make deploy-https ZTAS_SERVER_IP=192.168.2.2
```

## 1.4 Kiểm tra

```cmd
curl.exe --ssl-no-revoke https://ztas.ptit:8443/health
```

Kết quả phải có `"status":"UP"`.

---

# 2. Triển khai macOS Server

## 2.1 Cài công cụ một lần

Caddy chỉ cần trên MacBook khi MacBook là **server**.

```zsh
xcode-select --install
```

Cài Homebrew theo [brew.sh](https://brew.sh) nếu máy chưa có. Sau đó:

```zsh
brew install git cmake caddy
brew install --cask docker
open -a Docker
docker info
```

## 2.2 Clone source và lấy IP

```zsh
mkdir -p ~/source
cd ~/source
git clone https://github.com/huytan29/ZTAS_PoC.git
cd ZTAS_PoC
ipconfig getifaddr en0
```

Nếu không có IP ở `en0`:

```zsh
ifconfig | grep -E '^[a-z0-9]+:'
```

## 2.3 Deploy HTTPS

Ví dụ IP MacBook là `192.168.2.10`:

```zsh
cd ~/source/ZTAS_PoC
make deploy-https ZTAS_SERVER_IP=192.168.2.10
```

Với Mac Intel:

```zsh
make deploy-https ZTAS_SERVER_IP=192.168.2.10 VCPKG_TARGET_TRIPLET=x64-osx
```

Nhập mật khẩu macOS khi script yêu cầu cập nhật `/etc/hosts` và System Keychain.
Khi hoàn tất, trang đăng nhập ZTAS tự mở trong browser.
Kiểm tra:

```zsh
curl --fail https://ztas.ptit:8443/health
```

---

# 3. Thiết lập admin và tài khoản

## 3.1 Thiết lập admin lần đầu

Mở:

```text
https://ztas.ptit:8443/setup
```

Đặt mật khẩu mới cho `admin`. Khuyến nghị tối thiểu 12 ký tự gồm chữ hoa, chữ
thường, số và ký tự đặc biệt. Hệ thống lưu PBKDF2 hash, không lưu mật khẩu rõ.

Sau đó mở Dashboard:

```text
https://ztas.ptit:8443/dashboard
```

## 3.2 Tạo user

1. Menu **Tài khoản** → **Tạo tài khoản**.
2. Chọn role, đơn vị nghiệp vụ và nhiệm vụ/phạm vi.
3. Lưu **Account Key** xuất hiện trong hộp thoại; key chỉ hiện một lần.
4. Gửi key cho đúng người qua kênh an toàn.

Mật khẩu khởi tạo user PoC là `ptit@123`; hãy đổi khi dùng ngoài lab. Khi key
bị lộ, dùng **Cấp lại key** để vô hiệu hóa key cũ.

## 3.3 Quyền tài liệu và upload

| Role | Quyền đọc/nạp tối đa |
| --- | --- |
| Guest | Cấp 1 |
| Employee | Cấp 1–2 |
| Manager | Cấp 1–3; Cấp 3 cần Step-Up 2 |
| Engineer | Cấp 1–4; Cấp 4 cần Step-Up 3 |
| Business admin | Cấp 1–5 trong phạm vi; Cấp 5 cần Step-Up 5 |
| Admin kỹ thuật | Cấp 1–2; không đọc/nạp Cấp 3–5 |

Ngoài role, policy còn xét unit, task, thiết bị, IP, trust, location và MFA.

---

# 4. Cấp phát máy khách

## 4.1 Gói Client_PoC

Deploy tự tạo:

```text
Client_PoC/
├── Client/
│   ├── CAI-ZTAS-Windows.cmd
│   ├── CAI-ZTAS-Ubuntu.sh
│   └── CAI-ZTAS-macOS.command
├── ztas-local-ca.crt
└── ztas-client-config.sh
```

Gửi **nguyên thư mục `Client_PoC`**, không gửi riêng file trong `Client/`.
Có thể dùng LocalSend, USB quản trị, VMware Shared Folder, SMB đã xác thực hoặc
MDM.

Khi server đổi IP, tạo lại gói:

```cmd
mingw32-make client-installers ZTAS_SERVER_IP=192.168.2.2
```

```zsh
make client-installers ZTAS_SERVER_IP=192.168.2.10
```

Nếu có DNS nội bộ cho `ztas.ptit`, thêm `ZTAS_DNS_MODE=--use-dns` vào cuối lệnh
tạo gói để installer không sửa file hosts.

## 4.2 Windows client

1. Mở `Client_PoC\Client`.
2. Double-click `CAI-ZTAS-Windows.cmd`.
3. Chấp nhận UAC.
4. Browser tự mở trang kết nối thiết bị sau khi HTTPS được kiểm tra thành công.

Nếu cần, chuột phải file → **Run as administrator**.

## 4.3 Ubuntu/Linux client

Ví dụ gói ở `~/Downloads/Client_PoC`:

```bash
cd ~/Downloads/Client_PoC/Client
chmod +x CAI-ZTAS-Ubuntu.sh
./CAI-ZTAS-Ubuntu.sh
```

Nhập mật khẩu Ubuntu khi được hỏi. Nếu thư mục VMware không cho thực thi:

```bash
cd ~/Downloads/Client_PoC/Client
sh CAI-ZTAS-Ubuntu.sh
```

Firefox Ubuntu có thể dùng kho CA riêng. Nếu nó báo TLS warning, import:

```text
~/Downloads/Client_PoC/ztas-local-ca.crt
```

Trong Firefox: **Settings** → **Privacy & Security** → **Certificates** →
**View Certificates** → **Authorities** → **Import** → tích **Trust this CA to
identify websites**. Không chọn *Accept the Risk*.

## 4.4 macOS client

1. Mở `Client_PoC/Client` trong Finder.
2. Double-click `CAI-ZTAS-macOS.command` và nhập mật khẩu macOS.
3. Browser tự mở khi cài đặt thành công.

Nếu thiếu quyền thực thi:

```zsh
cd ~/Downloads/Client_PoC/Client
chmod +x CAI-ZTAS-macOS.command
./CAI-ZTAS-macOS.command
```

Gatekeeper có thể yêu cầu chuột phải → **Open** một lần trong lab. Với triển
khai thật, tạo PKG đã ký/notarized:

```zsh
make client-pkg ZTAS_SERVER_IP=192.168.2.10
```

## 4.5 Duyệt thiết bị

1. Browser máy khách mở `https://ztas.ptit:8443/connect-device`.
2. Nhập username, password và Account Key.
3. Admin vào **Thiết bị** → **Yêu cầu kết nối chờ phê duyệt**.
4. Kiểm tra máy, IP, profile, trust và location.
5. Chọn **Phân loại & cấp quyền**.
6. Máy khách tự chuyển sang trang Tài liệu sau khi được duyệt.

Thiết bị cũ mất Browser Device Proof dùng chế độ **Thiết bị đã cấp**, sau đó
admin chọn khôi phục thiết bị cũ.

---

# 5. Vận hành và kiểm thử

## 5.1 Lệnh hằng ngày

| Việc | Windows Server | macOS Server |
| --- | --- | --- |
| Build | `mingw32-make build` | `make build` |
| Chạy đầy đủ và mở trang đăng nhập | `mingw32-make run` | `make run` |
| Dừng ZTAS/Caddy | `mingw32-make stop` | `make stop` |
| Dừng cả OPA | `mingw32-make down` | `make down` |
| Xem audit log | `mingw32-make logs` | `make logs` |

Sau `git pull`:

```cmd
cd /d E:\ZTAS_PoC
git pull
set VCPKG_FORCE_SYSTEM_BINARIES=
mingw32-make build
```

```zsh
cd ~/source/ZTAS_PoC
git pull
make build
```

Vcpkg tự tải dependency vào `.vcpkg/`; không cần đặt `VCPKG_ROOT` toàn cục.

## 5.2 Chạy 5 kịch bản đề cương

Docker Desktop phải chạy.

```cmd
cd /d E:\ZTAS_PoC
mingw32-make scenario-test
```

```zsh
cd ~/source/ZTAS_PoC
make scenario-test
```

Kết quả `PASS`/`FAIL` và báo cáo JSON:

```text
runtime/test-reports/scenario-report.json
```

Các kịch bản: đúng unit/task, sai unit, thiết bị untrusted, manager sau
Step-Up, admin kỹ thuật bị từ chối tài liệu cấp cao.

---

# 6. Xử lý sự cố

| Hiện tượng | Cách xử lý |
| --- | --- |
| `mingw32-make is not recognized` | Thêm `C:\msys64\mingw64\bin` vào PATH, mở CMD mới. |
| `cmake is not recognized` | Cài CMake 4.4.4+, chọn *Add CMake to PATH*, mở CMD mới. |
| `Could not fetch powershell-core` | Chạy `set VCPKG_FORCE_SYSTEM_BINARIES=` rồi build lại. |
| Docker chưa sẵn sàng | Mở Docker Desktop, đợi **Engine running**. |
| Caddy không khởi động | Xem `runtime/caddy.stderr.log`, kiểm tra cổng 8443. |
| Không mở được `ztas.ptit` | Kiểm tra IP/DNS/firewall, tạo lại `Client_PoC` với IP mới. |
| Firefox Ubuntu cảnh báo HTTPS | Import `ztas-local-ca.crt` theo Phần 4.3. |
| Không đọc/nạp được tệp | Kiểm tra role, unit, task, trust, IP và MFA trong menu Nhật ký. |

---

# 7. Audit và dữ liệu nhạy cảm

- Audit log ở `data/logs/`, giữ **5 ngày lịch**.
- Menu **Nhật ký** → **Lưu riêng / tải** tạo snapshot tại `data/saved-logs/`.
- Không commit/chia sẻ Account Key, Device Key, mật khẩu, CA private key,
  `runtime/`, `data/device_credentials.json` hoặc tài liệu thật.

Phân vùng tài liệu server:

```text
data/documents/public/
data/documents/internal/
data/documents/confidential/
data/documents/secret/
data/documents/restricted/
```

## Tài liệu chi tiết

- [Quy trình HTTPS đa nền tảng](docs/QUY_TRINH_HTTPS_DA_NEN_TANG.md)
- [Kết nối thiết bị bằng Account Key](docs/account-key-device-connection.md)
- [Cấp phát và khôi phục thiết bị](docs/device-enrollment.md)
- [Kết nối VMware/Docker](docs/vmware-docker-device-access.md)
