#pragma once

#include <mutex>
#include <string>

struct DeviceOperationResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string device_id;
    std::string device_key;
    int trust_level = 0;
    std::string location_id;
    std::string device_name;
    std::string device_type;
    std::string enrollment_profile;
};

// Quan ly vong doi thiet bi trong PoC: cap phat va thu hoi dinh danh.
// Khoa dang ro chi duoc tra ve tai thoi diem cap phat; server chi luu hash.
class DeviceManagementService {
public:
    DeviceManagementService(
        std::string devices_policy_file,
        std::string locations_policy_file,
        std::string credentials_file,
        std::string device_environment_directory,
        std::string users_file
    );

    DeviceOperationResult enroll(
        const std::string& device_id,
        int trust_level,
        const std::string& location_id,
        const std::string& assigned_username,
        const std::string& device_name = "",
        const std::string& device_type = "unknown",
        const std::string& enrollment_profile = "manual",
        const std::string& allowed_ip_address = "",
        const std::string& declared_mac_address = "",
        const std::string& browser_proof_hash = ""
    ) const;

    DeviceOperationResult revoke(
        const std::string& device_id
    ) const;

    // Thay doi IP nguon duoc phep cho thiet bi da cap phat, khong sinh lai key.
    DeviceOperationResult update_allowed_ip(
        const std::string& device_id,
        const std::string& allowed_ip_address
    ) const;

    // Chan co chu dich: vo hieu hoa khoa va ghi lifecycle BLOCKED trong policy.
    DeviceOperationResult block(
        const std::string& device_id
    ) const;

    // Xoa vinh vien khoi policy, credentials, file .env va lien ket user.
    // Audit log khong bi xoa de giu bang chung su kien.
    DeviceOperationResult remove(
        const std::string& device_id
    ) const;

private:
    std::string devices_policy_file_;
    std::string locations_policy_file_;
    std::string credentials_file_;
    std::string device_environment_directory_;
    std::string users_file_;
    mutable std::mutex mutex_;
};
