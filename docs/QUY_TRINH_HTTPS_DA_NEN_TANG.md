# Quy trình triển khai HTTPS đa nền tảng cho ZTAS

**Trạng thái:** Bản đề xuất để xem xét trước khi triển khai đại trà.  
**Phạm vi:** Server chạy Windows hoặc macOS; máy khách Windows, Ubuntu và
macOS; mạng nội bộ/lab; hostname thống nhất `ztas.ptit`.

## 1. Mục tiêu triển khai

Người dùng cuối không cài ứng dụng HTTPS, không chép CA thủ công và không sửa
file hosts. Trên mọi thiết bị đã được cấp phát, người dùng chỉ truy cập:

```text
https://ztas.ptit:8443
```

và đăng nhập bằng tài khoản đã được cấp. ZTAS tiếp tục xác minh thiết bị,
Browser Device Proof, role, vùng tài liệu và Step-up MFA theo policy.

## 2. Kiến trúc mục tiêu

```text
                         DNS nội bộ
                   ztas.ptit → IP Server
                               |
       ┌───────────────────────┴───────────────────────┐
       │                                               │
Windows Server                                  macOS Server
ZTAS + OPA + Caddy                              ZTAS + OPA + Caddy
HTTPS :8443                                     HTTPS :8443
       │                                               │
       └─────────────── chỉ một server hoạt động ──────┘
                               |
                    Internal CA / Private PKI
                               |
      ┌────────────────┬───────────────┬───────────────┐
      │                │               │               │
 Windows client    Ubuntu client    macOS client   VM template
  tin CA sẵn        tin CA sẵn       tin CA sẵn     tin CA sẵn
```

Windows và macOS là hai **phương án server thay thế**, không chạy đồng thời
trừ khi xây dựng cơ chế HA riêng. Chỉ chọn một máy chủ ZTAS hoạt động cho mỗi
môi trường để audit log, policy và dữ liệu không bị phân tán.

## 3. Thành phần và trách nhiệm

| Thành phần | Trách nhiệm |
| --- | --- |
| DNS nội bộ | Phân giải `ztas.ptit` về IPv4/IPv6 hiện tại của server. |
| Private CA | Ký chứng chỉ TLS của `ztas.ptit`; CA gốc được thiết bị quản trị tin cậy. |
| Caddy | Kết thúc TLS ở cổng 8443; chỉ chuyển tiếp nội bộ đến ZTAS `127.0.0.1:8020`. |
| ZTAS | Xác thực tài khoản/thiết bị, gọi OPA, cấp token ngắn hạn và ghi audit. |
| OPA | Đánh giá RBAC/PBAC, phân vùng tài liệu và Step-up MFA. |
| Quản trị viên | Cấp tài khoản/Account Key, duyệt thiết bị, thu hồi thiết bị/MFA, quản lý DNS và CA. |
| Người dùng | Mở link HTTPS và đăng nhập; không tự cài CA hoặc agent. |

## 4. Chuẩn bị hạ tầng một lần

### 4.1 DNS nội bộ

Quản trị viên tạo bản ghi nội bộ:

```text
ztas.ptit   A/AAAA   <IP hiện tại của server>
```

Không dùng IP trong URL. Khi server chuyển mạng hoặc đổi địa chỉ DHCP, chỉ cập
nhật bản ghi DNS; URL, cookie Browser Device Proof và chứng chỉ vẫn giữ nguyên.

Với lab chưa có DNS server, có thể dùng router hỗ trợ Local DNS/DNS Override.
File `hosts` chỉ là giải pháp thử nghiệm, không phải phương án triển khai đa
thiết bị.

### 4.2 Private CA

Caddy tạo và lưu CA/chứng chỉ tại `runtime/caddy-data`. CA gốc được xuất ra:

```text
runtime/ztas-local-ca.crt
```

Khóa riêng CA nằm trên server, không đưa vào máy khách, không commit Git và
phải được backup/mã hóa theo chính sách của đơn vị.

### 4.3 Phân phối CA theo nền tảng

Việc này do IT/admin thực hiện khi cấp phát thiết bị, không do người dùng cuối
thực hiện sau khi nhận máy.

| Loại máy khách | Phương án cấp CA đề xuất |
| --- | --- |
| Windows | Group Policy/Intune/MDM import CA vào `Trusted Root Certification Authorities`. |
| Ubuntu | Tích hợp CA vào Ubuntu golden image hoặc cloud-init, sau đó chạy `update-ca-certificates` trước khi bàn giao. |
| macOS | MDM/configuration profile đưa CA vào System Keychain ở chế độ Always Trust. |

Mọi thiết bị mới được tạo từ image/profile đã cấp CA sẽ truy cập HTTPS ngay.

## 5. Phương án server Windows

### 5.1 Điều kiện

- Mã nguồn tại `E:\ZTAS_PoC`.
- MinGW-w64, CMake, vcpkg, Docker Desktop sẵn sàng.
- Caddy tại `C:\Tools\Caddy\caddy.exe` hoặc cho phép bootstrap tải lần đầu.
- Có quyền Administrator để mở Firewall và cập nhật hạ tầng máy chủ.

### 5.2 Triển khai ban đầu

```cmd
cd /d E:\ZTAS_PoC
mingw32-make deploy-https ZTAS_SERVER_IP=<IP_WINDOWS_SERVER>
```

Lệnh này build ZTAS, chạy OPA, đặt backend ở `127.0.0.1:8020`, khởi động
Caddy HTTPS ở `8443`, mở Firewall cần thiết và xuất CA.

### 5.3 Vận hành hàng ngày

```cmd
cd /d E:\ZTAS_PoC
mingw32-make run
```

Người dùng truy cập `https://ztas.ptit:8443/dashboard`.

## 6. Phương án server macOS

### 6.1 Điều kiện

- Mã nguồn ZTAS đã clone.
- Homebrew, Docker Desktop và dependency C++ đã được cài.
- macOS Firewall cho phép Caddy nhận TCP 8443 trong mạng nội bộ.
- Có quyền `sudo` để quản trị hosts/Keychain ở giai đoạn bootstrap.

### 6.2 Triển khai ban đầu

```bash
cd /duong-dan/ZTAS_PoC
make deploy-https ZTAS_SERVER_IP=<IP_MACBOOK_SERVER>
```

Script cài Caddy qua Homebrew nếu cần, build/chạy ZTAS + OPA + HTTPS proxy,
xuất CA và thêm CA vào System Keychain của máy server.

### 6.3 Vận hành hàng ngày

```bash
cd /duong-dan/ZTAS_PoC
make run
```

## 7. Quy trình cấp phát máy khách

1. IT/admin cấp máy hoặc VM từ golden image/profile đã tin CA và nhận DNS nội bộ.
2. Người dùng mở `https://ztas.ptit:8443`.
3. Nếu thiết bị chưa từng được duyệt, người dùng mở `/connect-device`, nhập
   tài khoản, mật khẩu và Account Key được cấp.
4. ZTAS thu thập thông tin trình duyệt/thiết bị, tạo Browser Device Proof và
   gửi yêu cầu đến admin.
5. Admin xác minh bối cảnh, gán role/trust/vùng và duyệt thiết bị.
6. Trình duyệt tự nhận phiên đăng nhập; người dùng chỉ đọc các vùng tài liệu
   theo role và policy.

Browser Device Proof được lưu cookie HttpOnly/Secure theo hostname
`ztas.ptit`; không yêu cầu cài agent trên máy khách.

## 8. Vận hành khi server đổi mạng

1. Server nhận IP mới.
2. Admin cập nhật bản ghi DNS nội bộ `ztas.ptit` về IP mới.
3. Nếu cần restart server, chạy `make run` tại server.
4. Người dùng tiếp tục mở cùng URL; không thay hosts, CA hoặc URL.

Nếu DNS và hostname không đổi, không cần đăng ký lại Browser Device Proof.

## 9. Kiểm thử chấp nhận

| Kịch bản | Kết quả cần đạt |
| --- | --- |
| Windows client mở link | Trình duyệt hiển thị HTTPS hợp lệ, không cảnh báo CA. |
| Ubuntu VM mở link | HTTPS hợp lệ, không cần chép/tạo file trên VM sau khi cấp phát. |
| macOS client mở link | HTTPS hợp lệ qua System Keychain/MDM. |
| User chưa được gán thiết bị | Bị từ chối hoặc chuyển sang quy trình cấp phát. |
| User role cấp 2 chọn tài liệu cấp 3 | Bị từ chối/Step-up theo policy. |
| Server đổi IP | Sau khi DNS cập nhật, URL cũ tiếp tục truy cập được. |
| Admin thu hồi thiết bị/MFA | Phiên truy cập tiếp theo bị từ chối và có audit log. |

## 10. Giới hạn và định hướng triển khai thật

- Private CA phù hợp lab/doanh nghiệp có quản trị thiết bị; CA không được tự
  động cài từ server vào thiết bị không quản trị.
- DNS nội bộ và phân phối CA bằng GPO/MDM là phần hạ tầng, không thay thế
  Zero Trust policy của ZTAS.
- Khi triển khai ngoài Internet, thay Private CA bằng domain công khai và CA
  công khai (ví dụ Let's Encrypt), vẫn giữ nguyên luồng ZTAS/OPA.
- Chỉ cổng HTTPS 8443 được công bố; ZTAS 8020 và OPA 8181 chỉ lắng nghe nội bộ.

---

# Phần II — Hướng dẫn triển khai từng bước

## Bước 0 — Chọn mô hình và chuẩn bị thông tin

Trước khi triển khai, admin xác nhận bốn thông tin sau:

| Thông tin | Giá trị mẫu | Ghi chú |
| --- | --- | --- |
| Máy chủ đang hoạt động | Windows hoặc MacBook | Chỉ chọn **một** máy cho một môi trường. |
| Hostname dịch vụ | `ztas.ptit` | Không đổi giữa các lần server đổi IP. |
| Cổng HTTPS | `8443` | Không cần quyền bind cổng 443; phù hợp lab. |
| IPv4 hiện thời server | `192.168.2.2` | Cập nhật vào DNS nội bộ, không đưa vào URL người dùng. |

Chuẩn bị Docker Desktop đang chạy và source code ZTAS đã ở máy server. Không
thực hiện đồng thời Windows server và macOS server trên cùng hostname.

## Bước 1A — Khởi tạo server Windows

### 1A.1 Kiểm tra công cụ

Mở CMD và kiểm tra:

```cmd
where mingw32-make
where g++
docker info
```

Nếu Docker chưa sẵn sàng, mở Docker Desktop trước. Xác định IPv4 LAN bằng:

```cmd
ipconfig
```

### 1A.2 Bootstrap HTTPS

Mở **CMD bằng Run as administrator**, thay IP dưới đây bằng IP LAN hiện thời:

```cmd
cd /d E:\ZTAS_PoC
mingw32-make deploy-https ZTAS_SERVER_IP=192.168.2.2
```

Bootstrap sẽ build ZTAS, khởi động OPA/Caddy, mở cổng 8443 trong Private
Firewall, tạo Private CA và xuất CA tại:

```text
E:\ZTAS_PoC\runtime\ztas-local-ca.crt
```

### 1A.3 Kiểm tra server

```cmd
curl.exe --ssl-no-revoke https://ztas.ptit:8443/health
type runtime\caddy.stderr.log
type runtime\ztas.stderr.log
```

Kết quả `/health` phải chứa `"status":"UP"`; log lỗi phải trống hoặc không
có lỗi mức `error` sau thời điểm khởi động.

## Bước 1B — Khởi tạo server macOS

Chỉ thực hiện bước này nếu MacBook được chọn làm server thay cho Windows.

### 1B.1 Chuẩn bị lần đầu

Mở Terminal:

```bash
brew install cmake cpp-httplib nlohmann-json openssl@3 sqlite caddy
open -a Docker
```

Chờ Docker Desktop sẵn sàng, sau đó xác định IPv4 Wi-Fi/LAN. Với đa số
MacBook dùng Wi-Fi:

```bash
ipconfig getifaddr en0
```

Nếu không có kết quả, xác định interface của default route rồi lấy IP của
interface đó.

### 1B.2 Bootstrap HTTPS

```bash
cd /duong-dan/ZTAS_PoC
make deploy-https ZTAS_SERVER_IP=192.168.2.10
```

Script có thể hỏi mật khẩu `sudo` để cập nhật hosts/Keychain trên MacBook.
Nếu macOS Firewall hỏi quyền mạng cho Caddy, chọn **Allow**.

### 1B.3 Kiểm tra server

```bash
curl --cacert runtime/ztas-local-ca.crt https://ztas.ptit:8443/health
tail -n 80 runtime/caddy.stderr.log
tail -n 80 runtime/ztas.stderr.log
```

## Bước 2 — Cấu hình DNS nội bộ

Đây là bước giúp người dùng không phải sửa `hosts` trên từng máy.

Trên DNS server hoặc router có Local DNS/DNS Override, tạo bản ghi:

```text
Tên:     ztas.ptit
Kiểu:    A
Địa chỉ: <IPv4 hiện thời của Windows/MacBook server>
TTL:     300 giây (khuyến nghị cho lab di động)
```

Ví dụ:

```text
ztas.ptit  A  192.168.2.2
```

Kiểm tra từ một máy client:

```text
nslookup ztas.ptit
```

Kết quả phải trả về IP server. Khi server đổi mạng, admin cập nhật **một** bản
ghi DNS này; người dùng vẫn dùng nguyên URL.

## Bước 3 — Cấp CA cho thiết bị trước khi bàn giao

CA chỉ được phân phối bởi IT/admin trong giai đoạn cấp máy. Không gửi CA qua
HTTP, email không kiểm chứng hoặc Git repository công khai.

Admin chép đồng thời CA và script phù hợp (`provision-client-windows.cmd`,
`provision-client-ubuntu.sh` hoặc `provision-client-macos.sh`) sang máy khách
qua kênh quản trị tin cậy. Script in SHA-256 fingerprint của CA trước khi cài,
cài CA vào trust store, cấu hình `ztas.ptit` và gọi `/health` để xác minh.

Để bàn giao cho end user không biết dùng dòng lệnh, admin tạo bundle đã cấu
hình sẵn từ server:

```text
Windows server: mingw32-make client-installers ZTAS_SERVER_IP=192.168.2.2
macOS server:   make client-installers ZTAS_SERVER_IP=192.168.2.10
```

Nếu DNS nội bộ đã có bản ghi `ztas.ptit`, thêm
`ZTAS_DNS_MODE=--use-dns` vào lệnh tạo bundle; client sẽ không bị ghi đè
file hosts.

Lệnh tạo `Client_PoC/`. Admin chép hoặc chia sẻ **nguyên thư
mục** này cho người dùng qua kênh tin cậy; không cần nén/giải nén. Người dùng
chỉ mở đúng tệp theo hệ điều hành:

Khi server được khởi tạo bằng `deploy-https`, thư mục này được sinh tự động
sau khi Caddy tạo CA. Do đó đây là artifact luôn đi cùng đúng server, hostname
và CA hiện tại, không phải một bộ tools chung tạo thủ công.

| Máy khách | Tệp người dùng mở | Phản hồi bắt buộc của hệ điều hành |
| --- | --- | --- |
| Windows | `CAI-ZTAS-Windows.cmd` | Chấp nhận hộp thoại UAC. |
| Ubuntu | `CAI-ZTAS-Ubuntu.sh` | Nhập mật khẩu local administrator. |
| macOS | `CAI-ZTAS-macOS.command` | Nhập mật khẩu local administrator. |

Không thể cài chứng chỉ CA hoàn toàn im lặng trên thiết bị cá nhân không được
quản trị: Windows, Ubuntu và macOS đều cố ý yêu cầu quyền hệ thống. Với môi
trường doanh nghiệp, thay bundle bằng GPO/Intune/MDM hoặc golden image để người
dùng không thấy bất kỳ bước cài đặt nào.

### 3.1 Windows client

Trong doanh nghiệp, dùng Group Policy/Intune/MDM để import CA vào kho Root của
máy tính. Trong lab, admin tạo Windows golden image và chạy một lần:

```cmd
scripts\provision-client-windows.cmd 192.168.2.2 C:\Provisioning\ztas-local-ca.crt
```

Sau khi tạo image/clone, người dùng Windows chỉ mở link HTTPS.

### 3.2 Ubuntu client hoặc Ubuntu VM template

Trên Ubuntu golden image, admin chạy một lần:

```bash
sudo sh scripts/provision-client-ubuntu.sh \
  192.168.2.2 ~/Downloads/ztas-local-ca.crt
```

Sau đó tắt VM và clone/snapshot image. Nếu Firefox không dùng system trust
store, admin import cùng CA vào Firefox trong golden image trước khi clone.

### 3.3 macOS client

Trong môi trường quản trị, dùng MDM/configuration profile để đưa CA vào System
Keychain ở chế độ tin cậy. Trong lab, admin chạy trên golden image:

```bash
sudo sh scripts/provision-client-macos.sh \
  192.168.2.2 ~/Downloads/ztas-local-ca.crt
```

## Bước 4 — Cấp phát thiết bị và quyền truy cập

1. Bàn giao thiết bị đã nhận DNS nội bộ và CA.
2. Người dùng mở `https://ztas.ptit:8443`.
3. Người dùng đăng nhập bằng tài khoản hệ thống.
4. Với thiết bị mới, người dùng truy cập `/connect-device`, nhập tài khoản,
   mật khẩu và Account Key.
5. Admin xem yêu cầu trên Dashboard, xác minh thông tin, gán thiết bị với
   tài khoản/role/trust và phê duyệt.
6. Người dùng tự nhận phiên browser và truy cập danh sách tài liệu được policy
   cho phép.

Không có file thực thi ZTAS, CA hay script nào được yêu cầu từ người dùng sau
khi thiết bị đã được cấp phát.

## Bước 5 — Kiểm thử trước khi bàn giao

Thực hiện với ít nhất một Windows client, một Ubuntu VM và một macOS client:

1. Mở `https://ztas.ptit:8443`; kiểm tra biểu tượng HTTPS hợp lệ.
2. Đăng nhập bằng tài khoản đúng được gán cho thiết bị; xác nhận truy cập được
   các cấp tài liệu hợp lệ.
3. Đăng nhập bằng tài khoản khác không được gán thiết bị; xác nhận hệ thống
   từ chối và audit log có sự kiện.
4. Thử mở tài liệu cấp 3 trở lên; xác nhận Step-up MFA xuất hiện.
5. Nhập sai MFA 3 lần; xác nhận thiết bị bị khóa và chỉ admin có thể gỡ khóa.
6. Thu hồi thiết bị tại Dashboard; xác nhận phiên/tài liệu tiếp theo bị từ chối.
7. Đổi IP server trong DNS nội bộ; xác nhận URL `ztas.ptit` vẫn hoạt động sau
   khi DNS cập nhật và client refresh DNS.

## Bước 6 — Vận hành, backup và khôi phục

Mỗi lần server reboot, admin chỉ cần chạy:

```text
Windows:  mingw32-make run
macOS:    make run
```

Sao lưu định kỳ, với quyền truy cập giới hạn:

```text
data/users.json
data/device_credentials.json
data/ztas.db
data/logs/
data/documents/
runtime/caddy-data/
runtime/ztas.env
```

Không commit các tệp này vào Git. Nếu khôi phục server sang máy khác, khôi
phục cả `runtime/caddy-data/` để giữ CA cũ; nếu tạo CA mới, toàn bộ golden
image/client trust store phải được cập nhật CA mới.
