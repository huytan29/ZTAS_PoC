#pragma once

#include <mutex>
#include <string>

struct DiscoveryResult {
    bool success = false;
    bool first_seen = false;
    std::string device_id;
};

// Luu vet may yeu cau lan dau. Day la phat hien, khong phai cap quyen.
class DeviceDiscoveryService {
public:
    explicit DeviceDiscoveryService(std::string discovery_file);

    DiscoveryResult record_attempt(
        const std::string& device_id,
        const std::string& location_id,
        const std::string& user_agent
    ) const;

private:
    std::string discovery_file_;
    mutable std::mutex mutex_;
};
