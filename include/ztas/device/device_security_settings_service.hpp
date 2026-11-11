#pragma once

#include <mutex>
#include <string>

struct DeviceSecuritySettings {
    bool mac_capture_enabled = false;
};

// Luu cai dat nhay cam tach khoi policy thiet bi. MAC mac dinh khong duoc
// thu thap va chi admin moi co the thay doi qua API da xac thuc.
class DeviceSecuritySettingsService {
public:
    explicit DeviceSecuritySettingsService(std::string settings_file);

    DeviceSecuritySettings get() const;
    bool set_mac_capture_enabled(bool enabled);

private:
    std::string settings_file_;
    mutable std::mutex mutex_;
};
