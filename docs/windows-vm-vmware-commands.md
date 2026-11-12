# Hướng dẫn kết nối Windows VM (VMware) vào ZTAS

> Dùng cho **một Windows VM mới**. Lệnh phía máy ảo chạy trong **Command
> Prompt (CMD)**, không cần thay đổi PowerShell Execution Policy.

## A. Chuẩn bị VMware và Windows host

1. Bật Windows VM trong VMware Workstation, dùng mạng **NAT** hoặc **Bridged**.
2. Trên Windows host, mở CMD tại `E:\ZTAS_PoC` và chạy:

   ```cmd
   mingw32-make run
   ```

3. Mở `http://localhost:8020/dashboard`, đăng nhập Admin, tạo tài khoản cho
   VM (ví dụ `winvm-employee`, role `employee`) và cấp **Mã đăng ký** với
   profile `Managed VM`.

## B. Kiểm tra mạng từ Windows VM

Mở **CMD** trong Windows VM:

```cmd
ipconfig
set "ZTAS_URL=http://192.168.2.1:8020"
curl.exe "%ZTAS_URL%/health"
```

Kết quả đúng có chứa `"status":"UP"`.

`192.168.2.1` là IP host dùng trong môi trường VMware PoC hiện tại. Nếu VM
không kết nối được, thay bằng IP Windows host mà VM thấy được. Không dùng
`localhost` trên VM vì nó chỉ trỏ về chính VM.

## C. Gửi yêu cầu kết nối một lần

Điền mã cấp trên Dashboard và đặt Device ID duy nhất, sau đó chạy trong CMD:

```cmd
set "DEVICE_ID=windows-vm-01"
set "DEVICE_NAME=Windows VMware 01"
set "ENROLLMENT_CODE=<dan-ma-dang-ky-tu-dashboard-vao-day>"

curl.exe -i -X POST "%ZTAS_URL%/api/connection-requests" ^
  -H "Content-Type: application/json" ^
  -d "{\"device_id\":\"%DEVICE_ID%\",\"device_name\":\"%DEVICE_NAME%\",\"device_type\":\"windows\",\"enrollment_code\":\"%ENROLLMENT_CODE%\"}"
```

Kết quả mong đợi:

```text
HTTP/1.1 202 Accepted
"status":"PENDING_ADMIN_APPROVAL"
```

Sau khi nhận `PENDING_ADMIN_APPROVAL`, **không chạy lại lệnh POST**. Mã đăng
ký là một lần và VM đang chờ Admin phê duyệt.

## D. Phê duyệt trên Windows host

Trong Dashboard → **Thiết bị** → **Yêu cầu kết nối chờ phê duyệt**:

1. Chọn `windows-vm-01`.
2. Chọn **Phân loại & cấp quyền**.
3. Chọn profile/trust phù hợp, ví dụ `Managed VM` — Trust 3,
   `lab-network`.
4. Dùng đúng IP được Dashboard quan sát trong yêu cầu; không tự đoán IP từ
   `ipconfig` nếu hai giá trị khác nhau.
5. Gán tài khoản `winvm-employee`, sau đó cấp phát và lưu Device Key.

Device Key không cần nhập khi đọc tài liệu qua trình duyệt, nhưng cần lưu an
toàn để dùng cho API/agent về sau. Nếu Key đã lộ, Admin cần thu hồi và đăng ký
lại thiết bị để sinh Key mới.

## E. Đăng nhập và kiểm tra tài liệu trên Windows VM

Mở Edge hoặc Chrome trong VM:

```text
http://192.168.2.1:8020/login
```

Đăng nhập bằng tài khoản đã gán, ví dụ `winvm-employee`. Vào menu **Tài liệu**
và nhấn `Ctrl + F5` lần đầu để nhận giao diện mới.

| Role | Các cấp tài liệu hiện trên VM |
| --- | --- |
| `guest` | Cấp 1 |
| `employee` | Cấp 1–2 |
| `manager` | Cấp 1–3 |
| `engineer` | Cấp 1–4 |
| `admin` | Cấp 1–5 |

## Xử lý nhanh

| Hiện tượng | Cách xử lý |
| --- | --- |
| `curl.exe .../health` không kết nối | Kiểm tra `mingw32-make run`, mạng VMware, Windows Firewall của host và IP host. |
| `ENROLLMENT_CODE_INVALID` | Mã đã hết hạn/đã dùng; tạo mã mới trên Dashboard. |
| `PENDING_ADMIN_APPROVAL` | Đây là trạng thái đúng; dừng lệnh và phê duyệt trên Dashboard. |
| `DEVICE_IP_NOT_ALLOWED` | Trong Dashboard, chọn **Cập nhật IP** cho thiết bị và dùng IP ZTAS ghi nhận trong audit log. |
| Không thấy đúng cấp tài liệu | Đăng xuất/đăng nhập lại, kiểm tra thiết bị là **Đã xác định** và nhấn `Ctrl + F5`. |
