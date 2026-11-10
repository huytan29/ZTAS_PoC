#pragma once

#include <mutex>
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
    std::string user_agent;
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
        const std::string& user_agent
    ) const;

    std::vector<PendingDeviceRequest> list_pending() const;

    bool resolve(const std::string& device_id) const;

private:
    std::string discovery_file_;
    mutable std::mutex mutex_;
};
