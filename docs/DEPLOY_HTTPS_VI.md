# Hướng dẫn triển khai HTTPS nội bộ

Tài liệu này triển khai ZTAS trên Windows Server và truy cập từ Ubuntu VM qua
hostname cố định `ztas.ptit`. Mô hình này dành cho mạng lab/luận văn; Caddy
tạo CA nội bộ miễn phí và ZTAS chỉ mở backend ở loopback.

## Kiến trúc

```text
Ubuntu VM / Windows client
       https://ztas.ptit:8443
                  |
               Caddy TLS
                  |
       http://127.0.0.1:8020
                  |
                 ZTAS + OPA
```

HTTP chỉ tồn tại giữa Caddy và ZTAS trên cùng máy chủ. Không mở cổng `8020`
cho mạng LAN.

## Điều kiện trước khi bắt đầu

- Windows là máy chủ, có mã nguồn tại `E:\ZTAS_PoC`.
- MinGW-w64, CMake, vcpkg và Docker Desktop đã hoạt động.
- Ubuntu VM và Windows server có thể liên lạc trong cùng mạng LAN/VMware.
- Chọn IPv4 hiện thời của Windows server. Ví dụ trong tài liệu: `192.168.2.2`.

## Lần triển khai đầu tiên trên Windows server

Mở **CMD bằng Run as administrator**, sau đó chạy:

```cmd
cd /d E:\ZTAS_PoC
mingw32-make deploy-https ZTAS_SERVER_IP=192.168.2.2
```

Script `scripts\deploy-https-windows.cmd` thực hiện các việc sau:

1. Kiểm tra quyền Administrator và địa chỉ IP.
2. Tải Caddy vào `C:\Tools\Caddy\caddy.exe` nếu máy chưa có.
3. Cập nhật hosts của Windows server với `192.168.2.2 ztas.ptit`.
4. Mở Windows Firewall TCP `8443` trong Private profile.
5. Build/provision ZTAS, khởi động OPA và Caddy.
6. Lưu CA/chứng chỉ ở `runtime\caddy-data` và xuất CA cho máy khách tại
   `runtime\ztas-local-ca.crt`.

Sau khi hoàn tất, truy cập Dashboard:

```text
https://ztas.ptit:8443/dashboard
```

### Xác minh tại Windows

Windows `curl` thường kiểm tra CRL/OCSP mà CA nội bộ không cung cấp. Chỉ dùng
tham số sau để kiểm tra kỹ thuật bằng curl; trình duyệt vẫn phải tin CA bình
thường:

```cmd
curl.exe --ssl-no-revoke https://ztas.ptit:8443/health
```

Kết quả phải có `"status":"UP"`. Không truy cập Dashboard qua
`http://localhost:8020` hoặc `http://<IP>:8020`.

## Cấp tin cậy cho Ubuntu VM

1. Chép `E:\ZTAS_PoC\runtime\ztas-local-ca.crt` sang Ubuntu qua VMware Shared
   Folder. Không tải CA qua một HTTP server không được bảo vệ.
2. Trên Ubuntu, cài CA và hostname (thay đường dẫn shared folder thực tế):

```bash
sudo install -m 0644 \
  /mnt/hgfs/<shared-folder>/ztas-local-ca.crt \
  /usr/local/share/ca-certificates/ztas-local-ca.crt

sudo update-ca-certificates
sudo sh -c 'printf "192.168.2.2 ztas.ptit\\n" >> /etc/hosts'

curl -fsS https://ztas.ptit:8443/health
```

3. Mở Firefox tại `https://ztas.ptit:8443/dashboard`.

Nếu Firefox vẫn cảnh báo CA, vào **Settings → Privacy & Security →
Certificates → View Certificates → Authorities → Import**, chọn
`ztas-local-ca.crt`, rồi tin cậy CA cho website.

## Dùng MacBook làm máy chủ

MacBook dùng chính hostname `ztas.ptit` và cùng mô hình Caddy. Cài trước
Homebrew, Docker Desktop, CMake, các dependency của dự án; sau đó chạy:

```bash
cd /duong-dan/ZTAS_PoC
make deploy-https ZTAS_SERVER_IP=192.168.2.10
```

Script `scripts/deploy-https-macos.sh` tự cài Caddy qua Homebrew nếu cần, cập
nhật `/etc/hosts`, build/chạy ZTAS + OPA + Caddy, lưu CA trong
`runtime/caddy-data`, xuất `runtime/ztas-local-ca.crt` và thêm CA vào macOS
System Keychain. Script sẽ hỏi mật khẩu `sudo`; đây là cần thiết để thay đổi
hosts và trust store. Nếu macOS Firewall hỏi, chọn **Allow** cho Caddy.

Ubuntu VM vẫn cần trỏ `ztas.ptit` về IPv4 MacBook hiện tại và cài file CA theo
phần hướng dẫn phía trên. Khi MacBook đổi mạng, chạy lại lệnh với IP mới, rồi
cập nhật một dòng hosts/DNS trên máy khách.

## Chuyển từ URL/IP cũ sang `ztas.ptit`

Cookie Browser Device Proof gắn với hostname. Vì vậy thiết bị đã đăng ký trước
đây bằng URL IP hoặc `ztas.test` sẽ tạo một yêu cầu kết nối mới một lần khi mở:

```text
https://ztas.ptit:8443/connect-device
```

Nhập tên đăng nhập, mật khẩu và Account Key; admin phê duyệt yêu cầu mới. Sau
khi kiểm tra thành công, thu hồi thiết bị/định danh cũ để tránh trùng lặp.

## Vận hành thường ngày

Sau khi Windows reboot, chạy:

```cmd
cd /d E:\ZTAS_PoC
mingw32-make run
```

Lệnh này dùng lại CA đã có, khởi động ZTAS, OPA và Caddy. Dừng toàn bộ bằng:

```cmd
mingw32-make stop
```

## Khi Windows server đổi mạng

Ví dụ Windows server nhận IP mới `192.168.1.50`:

```cmd
cd /d E:\ZTAS_PoC
mingw32-make deploy-https ZTAS_SERVER_IP=192.168.1.50
```

Hostname, CA và URL không đổi. Cập nhật một dòng trên Ubuntu:

```text
192.168.1.50 ztas.ptit
```

Với nhiều máy khách, thay `/etc/hosts` bằng DNS nội bộ: chỉ cần cập nhật bản
ghi `ztas.ptit` khi IP Windows đổi.

## Xử lý sự cố

| Hiện tượng | Cách xử lý |
| --- | --- |
| `Caddy khong khoi dong` | Xem `runtime\caddy.stderr.log`; dừng Caddy cũ bằng `taskkill /F /IM caddy.exe`, sau đó chạy bootstrap lại. |
| Không mở được `ztas.ptit` | Kiểm tra hosts/DNS trỏ đúng IP, rồi chạy `ping ztas.ptit`. |
| Ubuntu báo chứng chỉ không tin cậy | Cài lại `ztas-local-ca.crt`, chạy `sudo update-ca-certificates`; import CA thủ công vào Firefox nếu cần. |
| Tài khoản cũ không nhận thiết bị | Mở `/connect-device` qua `ztas.ptit`, gửi yêu cầu mới và để admin phê duyệt. |
| Browser Network hiện HTTP | Đảm bảo trang đang mở là `https://ztas.ptit:8443`; HTTP ở log Caddy → ZTAS là loopback nội bộ, không phải lưu lượng máy khách. |
