# Truy cập PoC từ VMware và Docker

## Nguyên tắc Zero Trust

Máy ảo hoặc container **không** kết nối trực tiếp vào `data/ztas.db`.
Mọi yêu cầu đi qua ZTAS tại `/documents/...`; ZTAS xác thực tài khoản,
kiểm tra Device Key, gửi ngữ cảnh cho OPA, sau đó mới đọc đúng vùng dữ liệu
trong SQLite.

ZTAS trung tâm cũng là điểm ghi audit duy nhất. Dù client là Windows, macOS hay
Linux, chúng phải gọi cùng `ZTAS_URL` để nhật ký liên tục trong một luồng.

## 1. Máy mới gửi yêu cầu lần đầu

Máy phải khai báo Device ID và vùng mạng dự kiến. Lần đầu chưa có Device Key,
nên OPA sẽ từ chối với `DEVICE_NOT_REGISTERED`, đồng thời ZTAS ghi một sự kiện
`DEVICE_DISCOVERED` vào Audit. Đây là **phát hiện**, không phải cấp quyền.

Trên máy gửi yêu cầu, lấy access token của tài khoản (cần `jq`):

```bash
export ACCESS_TOKEN="$(curl -s -X POST "$ZTAS_URL/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .access_token)"
```

Trong PoC hiện tại, token admin chỉ phục vụ kiểm thử luồng. Khi demo nghiệp vụ,
dùng token của employee/manager/engineer tương ứng sau khi đã đặt mật khẩu cho
tài khoản đó.

Ví dụ, sau khi có access token của tài khoản hợp lệ:

```bash
curl -i "$ZTAS_URL/documents/public" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Device-ID: ubuntu-vm-01" \
  -H "X-Location-ID: lab-network"
```

## 2. Admin cấp phát sau khi phát hiện

Trên Dashboard, chọn **Thêm thiết bị** và điền chính xác:

1. Device ID đã xuất hiện trong Audit.
2. Trust Level (1–5).
3. Vùng mạng.
4. Tài khoản được gán.

Hệ thống sinh Device Key một lần và tải tệp `<device-id>.env`. Sao chép tệp này
vào đúng VMware VM hoặc Docker container. Thiết bị chỉ xuất hiện Dashboard sau
khi hoàn tất bốn thông tin trên.

## 3. VMware VM

`localhost` chỉ có ý nghĩa trên chính máy đang chạy ZTAS. Trong VMware, dùng IP
của máy host (macOS hoặc Windows) trên mạng mà VM nhìn thấy, ví dụ:

```bash
export ZTAS_URL="http://<MACBOOK_IP>:8020"
source ubuntu-vm-01.env
curl -i "$ZTAS_URL/documents/public" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Device-ID: $DEVICE_ID" \
  -H "X-Device-Key: $DEVICE_KEY" \
  -H "X-Location-ID: $LOCATION_ID"
```

Với VMware Bridged, dùng IP Wi-Fi/Ethernet của máy host. Với NAT, dùng địa chỉ
gateway/host do VMware cung cấp cho VM. Máy host phải cho phép kết nối tới cổng
8020 trên mạng lab. Trên Windows, tạo inbound firewall rule chỉ cho profile và
subnet lab cần thiết; không mở cổng công khai.

## 4. Docker device

Docker Desktop trên macOS và Windows cung cấp tên `host.docker.internal` để
container gọi về máy host:

```bash
docker run --rm \
  --env ZTAS_URL="http://host.docker.internal:8020" \
  --env DEVICE_ID="docker-client-01" \
  --env LOCATION_ID="lab-network" \
  --env ACCESS_TOKEN="$ACCESS_TOKEN" \
  curlimages/curl:8.12.1 sh -c '\
    curl -i "$ZTAS_URL/documents/public" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "X-Device-ID: $DEVICE_ID" \
      -H "X-Location-ID: $LOCATION_ID"'
```

Lệnh trên là lần phát hiện đầu tiên. Sau khi admin cấp phát, truyền thêm
`DEVICE_KEY` từ tệp `.env` được tải về. Không đưa Device Key vào Git hay log.
