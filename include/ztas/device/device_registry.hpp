#pragma once

#include <string>

// Xac thuc khoa dinh danh cua thiet bi truoc khi gui ngu canh truy cap den OPA.
// File credentials chi luu PBKDF2 hash, khong luu khoa thiet bi dang ro.
class DeviceRegistry {
public:
    explicit DeviceRegistry(std::string credentials_file);

    bool verify(
        const std::string& device_id,
        const std::string& device_key
    ) const;

private:
    std::string credentials_file_;
};
