#include "ztas/device/device_discovery_service.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

long long current_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

void write_json(const fs::path& path, const json& value) {
    fs::create_directories(path.parent_path());
    const fs::path temporary = path.string() + ".tmp";
    {
        std::ofstream file(temporary);
        if (!file) {
            throw std::runtime_error("Khong ghi duoc kho phat hien thiet bi");
        }
        file << value.dump(2) << '\n';
    }

    std::error_code error;
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
    }
    if (error) {
        throw std::runtime_error("Khong cap nhat duoc kho phat hien thiet bi");
    }
}

json read_discoveries(const fs::path& path) {
    json discoveries = {
        {"schema_version", 1},
        {"devices", json::object()}
    };

    if (fs::exists(path)) {
        std::ifstream file(path);
        discoveries = json::parse(file);
        if (!discoveries.contains("devices")) {
            discoveries["devices"] = json::object();
        }
    }

    return discoveries;
}

} // namespace

DeviceDiscoveryService::DeviceDiscoveryService(std::string discovery_file)
    : discovery_file_(std::move(discovery_file)) {}

DiscoveryResult DeviceDiscoveryService::record_attempt(
    const std::string& device_id,
    const std::string& location_id,
    const std::string& source_ip,
    const std::string& user_agent,
    const std::string& declared_mac_address,
    const std::string& device_name,
    const std::string& device_type,
    const std::string& enrollment_profile,
    const std::string& requested_username,
    bool enrollment_verified
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        const fs::path path(discovery_file_);
        json discoveries = read_discoveries(path);

        const long long now = current_epoch();
        const bool first_seen =
            !discoveries["devices"].contains(device_id);

        json& discovery = discoveries["devices"][device_id];
        if (first_seen) {
            discovery = {
                {"device_id", device_id},
                {"first_seen", now},
                {"attempt_count", 0}
            };
        }

        discovery["last_seen"] = now;
        discovery["location_id"] = location_id;
        discovery["source_ip"] = source_ip;
        discovery["user_agent"] = user_agent;
        if (!declared_mac_address.empty()) {
            discovery["declared_mac_address"] = declared_mac_address;
        }
        if (!device_name.empty()) discovery["device_name"] = device_name;
        if (!device_type.empty()) discovery["device_type"] = device_type;
        if (!enrollment_profile.empty()) discovery["enrollment_profile"] = enrollment_profile;
        if (!requested_username.empty()) discovery["requested_username"] = requested_username;
        discovery["enrollment_verified"] = enrollment_verified ||
            discovery.value("enrollment_verified", false);
        discovery["attempt_count"] = discovery.value("attempt_count", 0) + 1;
        discovery["status"] = "PENDING_APPROVAL";
        write_json(path, discoveries);

        return {true, first_seen, device_id};
    } catch (const std::exception&) {
        return {false, false, device_id};
    }
}

std::vector<PendingDeviceRequest> DeviceDiscoveryService::list_pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PendingDeviceRequest> requests;

    try {
        const json discoveries = read_discoveries(fs::path(discovery_file_));
        for (auto iterator = discoveries.at("devices").begin();
             iterator != discoveries.at("devices").end();
             ++iterator) {
            const json& discovery = iterator.value();
            if (discovery.value("status", "") != "PENDING_APPROVAL") {
                continue;
            }

            requests.push_back({
                iterator.key(),
                discovery.value("location_id", "unknown"),
                discovery.value("source_ip", "unknown"),
                discovery.value("declared_mac_address", ""),
                discovery.value("user_agent", "unknown"),
                discovery.value("device_name", ""),
                discovery.value("device_type", "unknown"),
                discovery.value("enrollment_profile", "manual"),
                discovery.value("requested_username", ""),
                discovery.value("enrollment_verified", false),
                discovery.value("first_seen", 0LL),
                discovery.value("last_seen", 0LL),
                discovery.value("attempt_count", 0)
            });
        }
    } catch (const std::exception&) {
        return {};
    }

    std::sort(
        requests.begin(), requests.end(),
        [](const PendingDeviceRequest& left, const PendingDeviceRequest& right) {
            return left.last_seen > right.last_seen;
        }
    );
    return requests;
}

bool DeviceDiscoveryService::resolve(const std::string& device_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        const fs::path path(discovery_file_);
        json discoveries = read_discoveries(path);
        if (!discoveries["devices"].contains(device_id)) {
            return false;
        }
        discoveries["devices"].erase(device_id);
        write_json(path, discoveries);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
