#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct DiscoveryResult {
    bool success = false;
    bool first_seen = false;
    std::string device_id;
};

struct PendingDeviceRequest {
    std::string device_id;
    std::string location_id;
    std::string source_ip;
    std::string declared_mac_address;
    std::string user_agent;
    std::string device_name;
    std::string device_type;
    std::string enrollment_profile;
    std::string requested_username;
    bool enrollment_verified = false;
    long long first_seen = 0;
    long long last_seen = 0;
    int attempt_count = 0;
};

// Luu vet may yeu cau lan dau. Day la phat hien, khong phai cap quyen.
class DeviceDiscoveryService {
public:
    explicit DeviceDiscoveryService(std::string discovery_file);

    DiscoveryResult record_attempt(
        const std::string& device_id,
        const std::string& location_id,
        const std::string& source_ip,
        const std::string& user_agent,
        const std::string& declared_mac_address = "",
        const std::string& device_name = "",
        const std::string& device_type = "",
        const std::string& enrollment_profile = "",
        const std::string& requested_username = "",
        bool enrollment_verified = false,
        const std::string& browser_device_proof = ""
    ) const;

    std::vector<PendingDeviceRequest> list_pending() const;

    bool resolve(const std::string& device_id) const;

    // Chi dung noi bo khi admin phe duyet mot yeu cau ket noi tu web. Gia tri
    // tra ve la hash, khong bao gio la bang chung thiet bi dang ro.
    std::optional<std::string> browser_proof_hash(
        const std::string& device_id
    ) const;

private:
    std::string discovery_file_;
    mutable std::mutex mutex_;
};
