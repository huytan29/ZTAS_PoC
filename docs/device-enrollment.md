# Cap phat khoa cho thiet bi da duoc phep

## Muc dich

`policies/devices.json` la danh sach thiet bi va trust level duoc phep trong
PoC. Tep nay khong chua khoa bi mat.

`provision_devices` tu dong cap mot khoa rieng cho moi thiet bi co
`registered: true`. Moi khoa chi duoc sinh mot lan; chay lai cong cu khong lam
doi khoa cua thiet bi da cap.

Moi buoc cap phat deu in ra terminal va ghi su kien JSON vao
`data/audit.jsonl`, de co the xem bang Dashboard sau khi ZTAS khoi dong.

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

## Them mot thiet bi moi

1. Them ban ghi vao `policies/devices.json` va dat `registered: true`.
2. Chay lai `provision_devices`.
3. Gan tep `.env` moi sinh vao container/VM cua thiet bi.

Trust level va location trong policy quy dinh thiet bi duoc truy cap muc tai
nguyen nao; khoa chi chung minh do la dung thiet bi da dang ky.
