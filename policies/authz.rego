package zerotrust.authz

policy_version := "ztas-1.0.0"

default decision := {
    "effect": "DENY",
    "rule_id": "ZTAS-9999",
    "reason_code": "POLICY_NOT_MATCHED",
    "severity": "high",
    "policy_version": "ztas-1.0.0",
    "current_auth_level": 1,
    "required_auth_level": 1
}

has_device if {
    data.devices[input.device.id]
}

has_role if {
    data.roles[input.subject.role]
}

has_resource if {
    data.resources[input.resource.id]
}

has_location if {
    data.locations[input.context.location_id]
}

valid_context if {
    has_device
    has_role
    has_resource
    has_location
}

device_registered if {
    data.devices[input.device.id].registered == true
}

device_blocked if {
    data.devices[input.device.id].lifecycle_status == "BLOCKED"
}

# Gia tri nay chi do ZTAS tao sau khi doi chieu Device ID va Device Key.
# Rego khong bao gio nhan hoac luu khoa bi mat cua thiet bi.
device_key_verified if {
    input.device.key_verified == true
}

# IP lay tu ket noi TCP ma ZTAS quan sat, co the la IPv4 hoac IPv6. Khong tin
# header do client tu khai bao. Danh sach IP duoc cap khi admin duyet thiet bi.
device_ip_verified if {
    input.device.ip_verified == true
}

# Tai khoan thuong co expires_at = 0. Guest nhan expires_at luc dang nhap,
# vi vay token guest tu mat hieu luc sau thoi gian tam cap quyen.
account_active if {
    input.subject.account_expires_at == 0
}

account_active if {
    input.subject.account_expires_at > time.now_ns() / 1000000000
}

# Moi tai khoan chi dung duoc tren thiet bi da gan trong users.json.
# "*" duoc danh rieng cho admin cua moi truong PoC.
account_device_bound if {
    input.subject.allowed_device_ids[_] == "*"
}

account_device_bound if {
    input.subject.allowed_device_ids[_] == input.device.id
}

location_matches_device if {
    data.devices[input.device.id].location_id ==
        input.context.location_id
}

role_sufficient if {
    data.roles[input.subject.role].level >=
        data.resources[input.resource.id].min_role_level
}

device_sufficient if {
    data.devices[input.device.id].trust_level >=
        data.resources[input.resource.id].min_device_trust
}

location_sufficient if {
    data.locations[input.context.location_id].level >=
        data.resources[input.resource.id].min_location_level
}

auth_sufficient if {
    input.subject.auth_level >=
        data.resources[input.resource.id].min_auth_level
}

# Admin van phai dang nhap tu thiet bi da dang ky, dung IP duoc cap va nam
# trong pham vi tai khoan. Sau khi cac dieu kien nen tang nay dung, admin co
# quyen doc toan bo phan vung tai lieu cua PoC ma khong phai step-up theo cap.
admin_full_access if {
    input.subject.role == "admin"
    valid_context
    device_registered
    not device_blocked
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
}

output(effect, rule_id, reason, severity, required_auth) := {
    "effect": effect,
    "rule_id": rule_id,
    "reason_code": reason,
    "severity": severity,
    "policy_version": policy_version,
    "current_auth_level": input.subject.auth_level,
    "required_auth_level": required_auth
}

decision := output(
    "DENY",
    "ZTAS-1001",
    "DEVICE_NOT_REGISTERED",
    "critical",
    1
) if {
    not has_device
}

decision := output(
    "DENY",
    "ZTAS-2001",
    "ROLE_NOT_DEFINED",
    "high",
    1
) if {
    has_device
    not has_role
}

decision := output(
    "DENY",
    "ZTAS-2002",
    "RESOURCE_NOT_DEFINED",
    "high",
    1
) if {
    has_device
    has_role
    not has_resource
}

decision := output(
    "DENY",
    "ZTAS-2003",
    "LOCATION_NOT_DEFINED",
    "high",
    1
) if {
    has_device
    has_role
    has_resource
    not has_location
}

decision := output(
    "DENY",
    "ZTAS-1007",
    "DEVICE_BLOCKED",
    "critical",
    1
) if {
    valid_context
    device_blocked
}

decision := output(
    "DENY",
    "ZTAS-1002",
    "DEVICE_REGISTRATION_INACTIVE",
    "critical",
    1
) if {
    valid_context
    not device_blocked
    not device_registered
}

decision := output(
    "DENY",
    "ZTAS-1004",
    "DEVICE_KEY_INVALID",
    "critical",
    1
) if {
    valid_context
    device_registered
    not device_key_verified
}

decision := output(
    "DENY",
    "ZTAS-1005",
    "ACCOUNT_EXPIRED",
    "high",
    1
) if {
    valid_context
    device_registered
    device_key_verified
    not account_active
}

decision := output(
    "DENY",
    "ZTAS-1008",
    "DEVICE_IP_NOT_ALLOWED",
    "critical",
    1
) if {
    valid_context
    device_registered
    device_key_verified
    not device_ip_verified
}

decision := output(
    "DENY",
    "ZTAS-1006",
    "ACCOUNT_DEVICE_BINDING_FAILED",
    "high",
    1
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    not account_device_bound
}

decision := output(
    "DENY",
    "ZTAS-2004",
    "LOCATION_NOT_ALLOWED_FOR_DEVICE",
    "high",
    1
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    not location_matches_device
}

decision := output(
    "DENY",
    "ZTAS-2005",
    "ROLE_LEVEL_INSUFFICIENT",
    "high",
    data.resources[input.resource.id].min_auth_level
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
    not role_sufficient
}

decision := output(
    "DENY",
    "ZTAS-1003",
    "DEVICE_TRUST_INSUFFICIENT",
    "high",
    data.resources[input.resource.id].min_auth_level
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
    role_sufficient
    not device_sufficient
    not admin_full_access
}

decision := output(
    "DENY",
    "ZTAS-2006",
    "LOCATION_LEVEL_INSUFFICIENT",
    "high",
    data.resources[input.resource.id].min_auth_level
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
    role_sufficient
    device_sufficient
    not location_sufficient
    not admin_full_access
}

decision := output(
    "STEP_UP",
    "ZTAS-3001",
    "AUTH_LEVEL_INSUFFICIENT",
    "medium",
    data.resources[input.resource.id].min_auth_level
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
    role_sufficient
    device_sufficient
    location_sufficient
    not auth_sufficient
    not admin_full_access
}

decision := output(
    "PERMIT",
    "ZTAS-4002",
    "ADMIN_GLOBAL_DOCUMENT_READ",
    "info",
    1
) if {
    admin_full_access
}

decision := output(
    "PERMIT",
    "ZTAS-4001",
    "ACCESS_GRANTED",
    "info",
    data.resources[input.resource.id].min_auth_level
) if {
    valid_context
    device_registered
    device_key_verified
    device_ip_verified
    account_active
    account_device_bound
    location_matches_device
    role_sufficient
    device_sufficient
    location_sufficient
    auth_sufficient
    not admin_full_access
}
