#include "ztas/device/device_security_settings_service.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <exception>
#include <fstream>
#include <system_error>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

json read_settings(const fs::path& path) {
    if (!fs::exists(path)) {
        return {{"mac_capture_enabled", false}};
    }
    std::ifstream file(path);
    return json::parse(file);
}

bool write_settings(const fs::path& path, const json& settings) {
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    if (error) return false;

    const fs::path temporary = path.string() + ".tmp";
    {
        std::ofstream file(temporary);
        if (!file) return false;
        file << settings.dump(2) << '\n';
    }
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
    }
    return !error;
}

} // namespace

DeviceSecuritySettingsService::DeviceSecuritySettingsService(
    std::string settings_file
) : settings_file_(std::move(settings_file)) {}

DeviceSecuritySettings DeviceSecuritySettingsService::get() const {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        const json settings = read_settings(settings_file_);
        return {settings.value("mac_capture_enabled", false)};
    } catch (const std::exception&) {
        return {};
    }
}

bool DeviceSecuritySettingsService::set_mac_capture_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        json settings = read_settings(settings_file_);
        settings["mac_capture_enabled"] = enabled;
        return write_settings(settings_file_, settings);
    } catch (const std::exception&) {
        return false;
    }
}
