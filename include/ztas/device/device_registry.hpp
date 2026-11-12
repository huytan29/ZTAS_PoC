#pragma once

#include <optional>
#include <string>
#include <vector>

struct ReaderDeviceContext {
    std::string device_id;
    std::string location_id;
};

// Xac thuc khoa dinh danh cua thiet bi truoc khi gui ngu canh truy cap den OPA.
// File credentials chi luu PBKDF2 hash, khong luu khoa thiet bi dang ro.
class DeviceRegistry {
public:
    DeviceRegistry(
        std::string credentials_file,
        std::string devices_policy_file
    );

    bool verify(
        const std::string& device_id,
        const std::string& device_key
    ) const;

    // Chi chap nhan IP ma server nhin thay tu ket noi TCP. Gia tri nay co the
    // la IPv4 hoac IPv6; khong doc X-Forwarded-For do client co the gia mao.
    bool verify_source_ip(
        const std::string& device_id,
        const std::string& source_ip
    ) const;

    // Cho phep dich vu phat hien bo qua mot yeu cau da duoc cap phat. Kiem
    // tra dong thoi policy thiet bi va credential dang hoat dong, khong chi
    // dua vao Device ID do client tu khai bao.
    bool is_active_registered(const std::string& device_id) const;

    std::optional<ReaderDeviceContext> resolve_reader_context(
        const std::vector<std::string>& allowed_device_ids,
        const std::string& source_ip
    ) const;

private:
    std::string credentials_file_;
    std::string devices_policy_file_;
};
