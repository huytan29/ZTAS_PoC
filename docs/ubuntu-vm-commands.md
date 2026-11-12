# Lệnh triển khai Ubuntu VM

> Dùng file này cho **một Ubuntu VM mới**. Thay các giá trị trong dấu ngoặc
> nhọn trước khi chạy. Không đưa Enrollment Code hoặc Device Key vào Git.

## A. Chuẩn bị trên Windows (Dashboard)

1. Mở `http://localhost:8020/dashboard` và đăng nhập admin.
2. Vào **Tài khoản**, tạo tài khoản cần dùng, ví dụ `ubuntu-employee` với
   role `employee`. Lưu mật khẩu khởi tạo do giao diện hiển thị.
3. Vào **Thiết bị** → **Cấp mã đăng ký**:
   - Profile: `Managed VM`
   - Tài khoản: `ubuntu-employee`
   - Thời hạn: 10 phút
4. Sao chép mã vừa tạo. Mã chỉ dùng được một lần.

## B. Chạy trên Ubuntu VM

Mở Terminal Ubuntu và dán từng khối lệnh sau.

### 1. Khai báo thông tin VM

```bash
export ZTAS_URL="http://192.168.2.1:8020"
export DEVICE_ID="ubuntu-vm-03"
export DEVICE_NAME="Ubuntu VM 03"
export ENROLLMENT_CODE="<dan-ma-dang-ky-tu-dashboard-vao-day>"
```

`192.168.2.1` là địa chỉ Windows host đã dùng trong môi trường VMware hiện
tại. Nếu máy host dùng địa chỉ khác, thay giá trị của `ZTAS_URL`.

### 2. Kiểm tra Ubuntu VM thấy được ZTAS

```bash
curl "$ZTAS_URL/health"
```

Kết quả đúng có chứa:

```json
{"status":"UP"}
```

### 3. Gửi yêu cầu kết nối — chỉ chạy đúng một lần

```bash
curl -i -X POST "$ZTAS_URL/api/connection-requests" \
  -H "Content-Type: application/json" \
  -d "{\"device_id\":\"$DEVICE_ID\",\"device_name\":\"$DEVICE_NAME\",\"device_type\":\"ubuntu\",\"enrollment_code\":\"$ENROLLMENT_CODE\"}"
```

Kết quả mong đợi:

```text
HTTP/1.1 202 Accepted
"status":"PENDING_ADMIN_APPROVAL"
```

Sau kết quả này, **không chạy lại lệnh POST**. Quay về Dashboard Windows để
phê duyệt yêu cầu.

## C. Phê duyệt trên Windows

Trong Dashboard → **Thiết bị** → **Yêu cầu kết nối chờ phê duyệt**:

1. Chọn đúng `ubuntu-vm-03`.
2. Chọn **Phân loại & cấp quyền**.
3. Kiểm tra IP lấy từ yêu cầu và gán tài khoản `ubuntu-employee`.
4. Cấp phát thiết bị, sau đó lưu Device Key hiển thị một lần.

Thiết bị phải xuất hiện trong danh sách với trạng thái **Đã xác định**.

## D. Đăng nhập đọc tài liệu trên Ubuntu

Mở Firefox trong Ubuntu VM:

```text
http://192.168.2.1:8020/login
```

Đăng nhập bằng tài khoản đã gán, sau đó vào menu **Tài liệu** và nhấn
`Ctrl + F5` một lần.

## E. Kiểm tra quyền theo role

| Role | Các cấp xuất hiện |
| --- | --- |
| `guest` | Cấp 1 |
| `employee` | Cấp 1–2 |
| `manager` | Cấp 1–3 |
| `engineer` | Cấp 1–4 |
| `admin` | Cấp 1–5 |

Role đúng vẫn cần thiết bị ở trạng thái **Đã xác định**, được gán đúng tài
khoản và kết nối từ IP đã cấp quyền.

## Xử lý nhanh

| Hiện tượng | Cách xử lý |
| --- | --- |
| `curl .../health` không kết nối được | Kiểm tra ZTAS đang chạy trên Windows bằng `mingw32-make run`, firewall và IP host. |
| `ENROLLMENT_CODE_INVALID` | Tạo mã mới trên Dashboard; mã cũ đã hết hạn hoặc đã được dùng. |
| `PENDING_ADMIN_APPROVAL` | Đây là đúng; phê duyệt trên Dashboard, không gửi POST lại. |
| Không hiện đúng các cấp tài liệu | Đăng xuất/đăng nhập lại và nhấn `Ctrl + F5`. |
