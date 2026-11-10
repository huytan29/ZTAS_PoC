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

Xem [hướng dẫn cấp phát thiết bị](docs/device-enrollment.md) và
[kết nối từ VM/Docker](docs/vmware-docker-device-access.md).
