# ZTAS PoC

PoC Zero Trust Access System (C++17): ZTAS xác thực người dùng và thiết bị,
hỏi OPA để lấy quyết định policy, rồi mới đọc tài liệu từ SQLite. Dịch vụ chính
chạy tại `http://localhost:8020`; OPA chạy trong Docker tại `127.0.0.1:8181`.

## Hỗ trợ nền tảng

Mã nguồn, build và luồng chạy hỗ trợ macOS và Windows x64. Không có thành phần
runtime nào phụ thuộc riêng vào macOS; khác biệt chỉ nằm ở công cụ cài đặt và
GNU Make và dependency manager.

| Nền tảng | Toolchain | Cài dependency |
| --- | --- | --- |
| macOS (Intel/Apple Silicon) | CMake 3.20+, Apple Clang | Homebrew |
| Windows 10/11 x64 hoặc Windows Server tương thích | CMake 3.20+, MinGW-w64 x64 | vcpkg (`x64-mingw-static`) |

Docker Desktop phải đang chạy trên cả hai nền tảng. `Makefile` là điểm vào duy
nhất để build/vận hành; không có script khởi động riêng.

## Khởi tạo source trên máy mới

Hai script bootstrap chỉ clone mã nguồn từ GitHub vào một thư mục mới; chúng
không tự cài dependency, không ghi đè source sẵn có và không tự chạy dịch vụ.
Vì vậy chúng an toàn để dùng lần đầu trên máy Windows hoặc macOS.

**Windows (CMD):** tải `scripts/bootstrap-windows.cmd` từ repository hoặc copy
script này sang máy mới, sau đó chạy:

```cmd
bootstrap-windows.cmd
```

Mặc định source sẽ nằm tại `%USERPROFILE%\source\ZTAS_PoC`. Có thể chỉ định
thư mục đích, ví dụ `bootstrap-windows.cmd E:\Projects\ZTAS_PoC`.

**macOS:**

```zsh
sh scripts/bootstrap-macos.sh
```

Mặc định source sẽ nằm tại `~/source/ZTAS_PoC`; có thể truyền thư mục đích làm
tham số thứ nhất. Sau khi clone, tiếp tục theo hướng dẫn build của từng nền
tảng phía dưới.

Windows 8.1 trở xuống không được hỗ trợ bởi phiên bản `cpp-httplib` hiện tại
(`0.65+`), nên dự án target Windows 10 trở lên.

## macOS

```zsh
brew install cmake cpp-httplib nlohmann-json openssl@3 sqlite
make build
```

Để khởi động đầy đủ môi trường demo sau khi build, chủ động chạy `make run`.
Lệnh này sẽ cấp Device Key cho các thiết bị `registered: true`, khởi động OPA
và sinh `runtime/ztas.env` nếu tệp chưa tồn tại.

## Windows

1. Cài **CMake**, **MinGW-w64 x64**, **Git**, **Docker Desktop**, vcpkg và
   **GNU Make**. Thư mục `bin` của MinGW-w64 phải nằm trong `PATH`; kiểm tra
   được cả `g++.exe` và `mingw32-make.exe` từ CMD.
2. Trong CMD, cài vcpkg một lần:

   ```cmd
   git clone https://github.com/microsoft/vcpkg "%USERPROFILE%\vcpkg"
   call "%USERPROFILE%\vcpkg\bootstrap-vcpkg.bat"
   ```

3. Trong CMD, đặt `VCPKG_ROOT` rồi build:

   ```cmd
   set VCPKG_ROOT=C:\Users\<ten-ban>\vcpkg
   set VCPKG_DEFAULT_TRIPLET=x64-mingw-static
   cd /d E:\ZTAS_PoC
   rmdir /s /q build\windows
   mingw32-make build
   ```

## Ứng dụng Windows và iPhone/iPad

Giao diện có thể cài như một **PWA** (Progressive Web App), dùng cùng code và
policy với bản web nên không có giao diện/luồng quyền riêng bị lệch.

- **Windows:** mở Dashboard bằng Microsoft Edge hoặc Chrome, chọn biểu tượng
  cài đặt ứng dụng trên thanh địa chỉ (hoặc menu `…` → *Apps* → *Install*).
- **iPhone/iPad:** mở URL Dashboard qua HTTPS trong Safari, chọn *Chia sẻ* →
  *Thêm vào Màn hình chính*. Safari sẽ mở ứng dụng ở chế độ độc lập.

PWA vẫn cần kết nối tới ZTAS để xác thực, kiểm tra policy và đọc dữ liệu; chỉ
các tài nguyên giao diện được cache cục bộ.

   Nếu bản MinGW-w64 của bạn cung cấp lệnh `make.exe`, `make build` cũng tương
   đương.

`rmdir /s /q build\windows` chỉ xóa tệp build sinh bởi CMake. Cần chạy nó khi
đổi từ một toolchain/triplet cũ (ví dụ `x64-windows`) sang MinGW-w64.

Vcpkg tự đọc [vcpkg.json](vcpkg.json) và cài `cpp-httplib`,
`nlohmann-json`, OpenSSL và SQLite theo manifest khi CMake cấu hình lần đầu.
Để giữ `VCPKG_ROOT` sau khi đóng CMD, đặt biến môi trường người dùng trỏ đến
thư mục vcpkg đó.

Không cần thay đổi PowerShell Execution Policy vì dự án không chạy `.ps1`.

## Lệnh Make

| Lệnh | Tác dụng |
| --- | --- |
| `make build` | Chỉ cấu hình và build C++ cho đúng nền tảng hiện tại. |
| `make provision` | Build, rồi cấp Device Key cho thiết bị đã đăng ký. |
| `make opa-up` | Khởi động OPA; Docker Desktop phải được mở sẵn. |
| `make run` | Chủ động chạy toàn bộ chuỗi provision + OPA + ZTAS. |
| `make logs` | Theo dõi audit log hôm nay. |
| `make stop` / `make down` | Dừng ZTAS / dừng cả ZTAS lẫn OPA. |

## Vận hành và dữ liệu nhạy cảm

- Không commit `runtime/`, `data/device_credentials.json`, database SQLite hay
  audit log; các đường dẫn này đã nằm trong `.gitignore`.
- Device Key chỉ xuất hiện lúc cấp phát. Cung cấp nó qua tệp `.env` của đúng
  thiết bị, không đặt trong policy, Git hoặc log.
- Server lắng nghe `0.0.0.0:8020` để máy ảo/container trong lab có thể kết nối.
  Chỉ mở firewall cổng này trong mạng lab tin cậy.

## Đặt tài liệu theo phân vùng quyền

Khi ZTAS khởi động, hệ thống tạo các thư mục sau để chứa tài liệu thực tế của
bạn. Có thể mở đường dẫn từ mục **Khu dữ liệu được bảo vệ** trên Dashboard
(cần quyền admin) và sao chép tệp trực tiếp vào đúng phân vùng:

```text
data/documents/public/
data/documents/internal/
data/documents/confidential/
data/documents/secret/
data/documents/restricted/
```

Các tệp không được commit Git. Tải một tệp qua
`GET /documents/<zone>/<filename>`; ZTAS xác thực token, Device Key, IP nguồn
và OPA trước khi trả nội dung. Ví dụ: `/documents/internal/ke-hoach.pdf`.
Không dùng tên tệp bắt đầu bằng dấu chấm, chứa thư mục con hoặc lớn hơn 25 MB.
Quyền của mỗi phân vùng dùng policy cùng cấp trong `policies/resources.json`.
Admin cũng có thể chọn **Tải tài liệu lên** ngay trên Dashboard, chọn phân vùng
rồi nạp tệp; chọn lại cùng tên sẽ thay thế tệp cũ trong chính phân vùng đó.

## Audit log tập trung và retention

- Audit log hoạt động được giữ **5 ngày lịch** trong `data/logs/`. Khi ZTAS
  khởi động hoặc ghi sự kiện mới, log cũ hơn 5 ngày sẽ tự xóa.
- Trên trang **Nhật ký**, chọn ngày rồi dùng **Lưu riêng / tải**. Hệ thống tạo
  snapshot JSONL tại `data/saved-logs/` và tải một bản JSON về máy; snapshot
  này không bị retention tự động xóa.
- Để audit xuyên suốt Windows, macOS và Linux, chỉ chạy **một ZTAS server trung
  tâm** và cấu hình mọi VM/container/client dùng cùng `ZTAS_URL`. Server này là
  nơi duy nhất ghi audit, nên log không bị chia thành từng máy build.
- Có thể đưa log của server trung tâm lên volume bền vững bằng biến môi trường
  `AUDIT_LOG_DIRECTORY`. Ví dụ đặt `AUDIT_LOG_DIRECTORY=/mnt/ztas-audit/logs`
  trên Linux/macOS hoặc `AUDIT_LOG_DIRECTORY=E:\ZTAS_Audit\logs` trên Windows
  trong `runtime/ztas.env`. Không chạy nhiều instance ZTAS cùng ghi vào một thư
  mục mạng; hãy để một instance trung tâm ghi log.

Xem [hướng dẫn cấp phát thiết bị](docs/device-enrollment.md) và
[kết nối từ VM/Docker](docs/vmware-docker-device-access.md).
