#include "ztas/device/device_discovery_service.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
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

} // namespace

DeviceDiscoveryService::DeviceDiscoveryService(std::string discovery_file)
    : discovery_file_(std::move(discovery_file)) {}

DiscoveryResult DeviceDiscoveryService::record_attempt(
    const std::string& device_id,
    const std::string& location_id,
    const std::string& user_agent
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        const fs::path path(discovery_file_);
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
        discovery["user_agent"] = user_agent;
        discovery["attempt_count"] = discovery.value("attempt_count", 0) + 1;
        discovery["status"] = "PENDING_APPROVAL";
        write_json(path, discoveries);

        return {true, first_seen, device_id};
    } catch (const std::exception&) {
        return {false, false, device_id};
    }
}
