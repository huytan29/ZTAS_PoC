# Cap phat khoa cho thiet bi da duoc phep

## Muc dich

`policies/devices.json` la danh sach thiet bi va trust level duoc phep trong
PoC. Tep nay khong chua khoa bi mat.

`provision_devices` tu dong cap mot khoa rieng cho moi thiet bi co
`registered: true`. Moi khoa chi duoc sinh mot lan; chay lai cong cu khong lam
doi khoa cua thiet bi da cap.

Moi buoc cap phat deu ghi su kien JSON theo ngay vao `data/logs/`, de co the
xem bang Dashboard sau khi ZTAS khoi dong.

## Tep duoc tao

- `data/device_credentials.json`: ZTAS doc tep nay de doi chieu PBKDF2 hash
  cua khoa. Tep khong chua khoa dang ro.
- `runtime/devices/<device-id>.env`: tep cau hinh rieng cua tung may ao/Docker
  client, gom `DEVICE_ID`, `DEVICE_KEY`, `LOCATION_ID`.

Ca hai duong dan da nam trong `.gitignore`.

## Chay cap phat

Tu thu muc goc Source, sau khi build:

```bash
./build/provision_devices \
  policies/devices.json \
  data/device_credentials.json \
  runtime/devices
```

Thiet bi `disabled-device-01` bi bo qua vi `registered` la `false`.

## Khi mot thiet bi yeu cau tai lieu

Thiet bi gui ba header:

```text
X-Device-ID: ubuntu-vm-01
X-Device-Key: <gia-tri DEVICE_KEY tu tep .env cua may nay>
X-Location-ID: lab-network
```

ZTAS kiem tra khoa truoc, sau do chi gui `key_verified: true/false` cho OPA.
OPA ap dung rule `ZTAS-1004 / DEVICE_KEY_INVALID` neu khoa sai hoac bi thieu.
Khoa bi mat khong bao gio duoc dua vao Rego hay audit log.

## Quy trinh khuyen dung: ma dang ky mot lan va phe duyet

Day la luong dung cho Ubuntu VM, Windows VM va Docker client. Chi ZTAS trung
tam chay tren MacBook ghi policy, cap Device Key va ghi audit log.

1. Admin mo Dashboard, chon **Cap ma dang ky**.
2. Chon profile va tai khoan se dung thiet bi:

   | Profile | Trust | Vung mac dinh |
   | --- | ---: | --- |
   | `guest` | 1 | `external-network` |
   | `unmanaged` | 2 | `external-network` |
   | `managed-vm` | 3 | `lab-network` |
   | `trusted` | 4 | `campus-network` |
   | `secure` | 5 | `secure-zone` |

3. Gui ma cho VM/client. Ma chi dung mot lan va mac dinh het han sau 10 phut.
4. Tren VM/client, gui yeu cau ket noi. Vi du tu Ubuntu:

   ```bash
   export ZTAS_URL=http://192.168.2.10:8020
   curl -i -X POST "$ZTAS_URL/api/connection-requests" \
     -H 'Content-Type: application/json' \
     -d '{"device_id":"ubuntu-vm-01","device_name":"Ubuntu VMware","device_type":"ubuntu","enrollment_code":"enr_DAN_MA_O_DAY"}'
   ```

5. Yeu cau chi hien trong hang cho `PENDING_APPROVAL`. Chua co Device Key nen
   khong the truy cap CSDL.
6. Admin nhan **Phan loai & cap quyen**, kiem tra profile, tai khoan, Trust va
   vung mang, roi cap phat. ZTAS tra Device Key mot lan va xoa yeu cau cho.
7. Luu file `.env` vua tai vao dung VM/client. Chi sau do thiet bi moi co the
   gui yeu cau tai nguyen va duoc OPA danh gia.

## Them thu cong mot thiet bi moi

1. Them ban ghi vao `policies/devices.json` va dat `registered: true`.
2. Chay lai `provision_devices`.
3. Gan tep `.env` moi sinh vao container/VM cua thiet bi.

Trust level va location trong policy quy dinh thiet bi duoc truy cap muc tai
nguyen nao; khoa chi chung minh do la dung thiet bi da dang ky.
