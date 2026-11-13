#include "ztas/device/device_management_service.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

bool valid_device_id(const std::string& id) {
    if (id.size() < 3 || id.size() > 64) {
        return false;
    }

    for (const char character : id) {
        if (!std::islower(static_cast<unsigned char>(character)) &&
            !std::isdigit(static_cast<unsigned char>(character)) &&
            character != '-') {
            return false;
        }
    }

    return id.front() != '-' && id.back() != '-';
}

std::string hex_encode(const unsigned char* input, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);

    for (std::size_t index = 0; index < length; ++index) {
        output.push_back(digits[(input[index] >> 4) & 0x0f]);
        output.push_back(digits[input[index] & 0x0f]);
    }
    return output;
}

std::string base64url_encode(const unsigned char* input, std::size_t length) {
    std::string output(4 * ((length + 2) / 3), '\0');
    const int encoded_size = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(output.data()),
        input,
        static_cast<int>(length)
    );
    output.resize(encoded_size);

    for (char& character : output) {
        if (character == '+') {
            character = '-';
        } else if (character == '/') {
            character = '_';
        }
    }

    while (!output.empty() && output.back() == '=') {
        output.pop_back();
    }

    return output;
}

void random_bytes(unsigned char* output, std::size_t length) {
    if (RAND_bytes(output, static_cast<int>(length)) != 1) {
        throw std::runtime_error("Khong the sinh so ngau nhien an toan");
    }
}

std::string create_device_key() {
    unsigned char bytes[32];
    random_bytes(bytes, sizeof(bytes));
    return "dvc_" + base64url_encode(bytes, sizeof(bytes));
}

std::string hash_key(const std::string& key) {
    constexpr int iterations = 200000;
    unsigned char salt[16];
    unsigned char derived[32];
    random_bytes(salt, sizeof(salt));

    if (PKCS5_PBKDF2_HMAC(
            key.c_str(),
            static_cast<int>(key.size()),
            salt,
            sizeof(salt),
            iterations,
            EVP_sha256(),
            sizeof(derived),
            derived
        ) != 1) {
        throw std::runtime_error("Khong the bam khoa thiet bi");
    }

    return "pbkdf2_sha256$" + std::to_string(iterations) + "$" +
        hex_encode(salt, sizeof(salt)) + "$" +
        hex_encode(derived, sizeof(derived));
}

json read_json(const fs::path& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Khong mo duoc tep: " + path.string());
    }
    return json::parse(file);
}

void write_json(const fs::path& path, const json& value) {
    fs::create_directories(path.parent_path());
    const fs::path temporary = path.string() + ".tmp";

    {
        std::ofstream file(temporary);
        if (!file) {
            throw std::runtime_error("Khong ghi duoc tep: " + path.string());
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
        throw std::runtime_error("Khong thay the duoc tep: " + path.string());
    }
}

void write_environment(
    const fs::path& path,
    const std::string& device_id,
    const std::string& key,
    const std::string& location_id
) {
    fs::create_directories(path.parent_path());
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Khong ghi duoc tep moi truong thiet bi");
    }

    file << "# Tu dong sinh boi ZTAS. Khong dua tep nay len Git.\n"
         << "DEVICE_ID=" << device_id << '\n'
         << "DEVICE_KEY=" << key << '\n'
         << "LOCATION_ID=" << location_id << '\n';
    file.close();

    std::error_code error;
    fs::permissions(
        path,
        fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace,
        error
    );
}

DeviceOperationResult failure(
    const std::string& code,
    const std::string& message
) {
    return {false, code, message, "", "", 0, "", "", "", ""};
}

} // namespace

DeviceManagementService::DeviceManagementService(
    std::string devices_policy_file,
    std::string locations_policy_file,
    std::string credentials_file,
    std::string device_environment_directory,
    std::string users_file
) : devices_policy_file_(std::move(devices_policy_file)),
    locations_policy_file_(std::move(locations_policy_file)),
    credentials_file_(std::move(credentials_file)),
    device_environment_directory_(std::move(device_environment_directory)),
    users_file_(std::move(users_file)) {}

DeviceOperationResult DeviceManagementService::enroll(
    const std::string& device_id,
    int trust_level,
    const std::string& location_id,
    const std::string& assigned_username,
    const std::string& device_name,
    const std::string& device_type,
    const std::string& enrollment_profile,
    const std::string& allowed_ip_address,
    const std::string& declared_mac_address,
    const std::string& browser_proof_hash
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!valid_device_id(device_id)) {
        return failure(
            "INVALID_DEVICE_ID",
            "Device ID chi gom chu thuong, so va dau gach ngang (3-64 ky tu)"
        );
    }

    if (trust_level < 1 || trust_level > 5) {
        return failure("INVALID_TRUST_LEVEL", "Trust level phai nam trong khoang 1-5");
    }

    if (assigned_username.empty()) {
        return failure(
            "ASSIGNED_USER_REQUIRED",
            "Can gan tai khoan cho thiet bi truoc khi cap phat"
        );
    }

    try {
        json devices_policy = read_json(devices_policy_file_);
        const json locations_policy = read_json(locations_policy_file_);

        if (!locations_policy.contains("locations") ||
            !locations_policy.at("locations").contains(location_id)) {
            return failure("INVALID_LOCATION", "Vung mang khong ton tai trong policy");
        }

        if (!devices_policy.contains("devices")) {
            devices_policy["devices"] = json::object();
        }

        json users_data = read_json(users_file_);
        if (!users_data.contains("users") || !users_data["users"].is_array()) {
            return failure("INVALID_USERS_STORE", "Kho nguoi dung khong dung dinh dang");
        }

        json* assigned_user = nullptr;
        for (auto& user : users_data["users"]) {
            if (user.value("username", "") == assigned_username) {
                assigned_user = &user;
                break;
            }
        }
        if (assigned_user == nullptr) {
            return failure("ASSIGNED_USER_NOT_FOUND", "Tai khoan duoc gan khong ton tai");
        }

        const bool exists = devices_policy["devices"].contains(device_id);
        if (exists && devices_policy["devices"][device_id].value(
                "lifecycle_status", ""
            ) == "BLOCKED") {
            return failure(
                "DEVICE_BLOCKED",
                "Thiet bi dang bi chan; hay xoa hoac xem xet lai cau hinh truoc khi cap phat"
            );
        }
        if (exists && devices_policy["devices"][device_id].value("registered", false)) {
            return failure("DEVICE_ALREADY_ACTIVE", "Device ID nay dang duoc dang ky");
        }

        json credentials = {
            {"schema_version", 1},
            {"devices", json::object()}
        };

        if (fs::exists(credentials_file_)) {
            credentials = read_json(credentials_file_);
            if (!credentials.contains("devices")) {
                return failure("INVALID_CREDENTIALS_STORE", "Kho thong tin xac thuc khong dung dinh dang");
            }
        }

        const std::string device_key = create_device_key();
        credentials["devices"][device_id] = {
            {"active", true},
            {"key_hash", hash_key(device_key)}
        };
        if (!browser_proof_hash.empty()) {
            credentials["devices"][device_id]["browser_proof_hash"] =
                browser_proof_hash;
        }

        devices_policy["devices"][device_id] = {
            {"registered", true},
            {"lifecycle_status", "ACTIVE"},
            {"trust_level", trust_level},
            {"location_id", location_id},
            {"device_name", device_name.empty() ? device_id : device_name},
            {"device_type", device_type.empty() ? "unknown" : device_type},
            {"enrollment_profile", enrollment_profile.empty() ? "manual" : enrollment_profile}
        };
        if (!allowed_ip_address.empty() && allowed_ip_address != "unknown") {
            devices_policy["devices"][device_id]["allowed_ip_addresses"] =
                json::array({allowed_ip_address});
        } else {
            devices_policy["devices"][device_id]["allowed_ip_addresses"] =
                json::array();
        }
        if (!declared_mac_address.empty()) {
            devices_policy["devices"][device_id]["declared_mac_addresses"] =
                json::array({declared_mac_address});
        }

        if (!assigned_user->contains("allowed_device_ids") ||
            !(*assigned_user)["allowed_device_ids"].is_array()) {
            (*assigned_user)["allowed_device_ids"] = json::array();
        }

        bool already_assigned = false;
        for (const auto& allowed_id : (*assigned_user)["allowed_device_ids"]) {
            already_assigned = allowed_id == device_id;
            if (already_assigned) {
                break;
            }
        }
        if (!already_assigned) {
            (*assigned_user)["allowed_device_ids"].push_back(device_id);
        }

        write_json(credentials_file_, credentials);
        write_json(users_file_, users_data);
        write_environment(
            fs::path(device_environment_directory_) / (device_id + ".env"),
            device_id,
            device_key,
            location_id
        );
        write_json(devices_policy_file_, devices_policy);

        return {
            true,
            exists ? "DEVICE_REENROLLED" : "DEVICE_ENROLLED",
            exists ? "Da dang ky lai va cap khoa moi cho thiet bi" : "Da cap phat thiet bi moi",
            device_id,
            device_key,
            trust_level,
            location_id,
            device_name.empty() ? device_id : device_name,
            device_type.empty() ? "unknown" : device_type,
            enrollment_profile.empty() ? "manual" : enrollment_profile
        };
    } catch (const std::exception& error) {
        return failure("DEVICE_ENROLLMENT_ERROR", error.what());
    }
}

DeviceOperationResult DeviceManagementService::revoke(
    const std::string& device_id
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!valid_device_id(device_id)) {
        return failure("INVALID_DEVICE_ID", "Device ID khong hop le");
    }

    try {
        json devices_policy = read_json(devices_policy_file_);
        if (!devices_policy.contains("devices") ||
            !devices_policy.at("devices").contains(device_id)) {
            return failure("DEVICE_NOT_FOUND", "Khong tim thay thiet bi trong policy");
        }

        json& device = devices_policy["devices"][device_id];
        device["registered"] = false;
        device["lifecycle_status"] = "REVOKED";

        json credentials = {
            {"schema_version", 1},
            {"devices", json::object()}
        };
        if (fs::exists(credentials_file_)) {
            credentials = read_json(credentials_file_);
            if (credentials.contains("devices")) {
                credentials["devices"].erase(device_id);
            }
        }

        write_json(credentials_file_, credentials);
        write_json(devices_policy_file_, devices_policy);

        std::error_code error;
        fs::remove(
            fs::path(device_environment_directory_) / (device_id + ".env"),
            error
        );

        return {
            true,
            "DEVICE_REVOKED",
            "Da thu hoi thiet bi va vo hieu hoa khoa dinh danh",
            device_id,
            "",
            device.value("trust_level", 0),
            device.value("location_id", ""),
            device.value("device_name", device_id),
            device.value("device_type", "unknown"),
            device.value("enrollment_profile", "manual")
        };
    } catch (const std::exception& error) {
        return failure("DEVICE_REVOCATION_ERROR", error.what());
    }
}

DeviceOperationResult DeviceManagementService::update_allowed_ip(
    const std::string& device_id,
    const std::string& allowed_ip_address
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!valid_device_id(device_id)) {
        return failure("INVALID_DEVICE_ID", "Device ID khong hop le");
    }
    if (allowed_ip_address.empty()) {
        return failure("INVALID_ALLOWED_IP", "Dia chi IP khong duoc de trong");
    }

    try {
        json devices_policy = read_json(devices_policy_file_);
        if (!devices_policy.contains("devices") ||
            !devices_policy.at("devices").contains(device_id)) {
            return failure("DEVICE_NOT_FOUND", "Khong tim thay thiet bi trong policy");
        }

        json& device = devices_policy["devices"][device_id];
        if (!device.value("registered", false)) {
            return failure("DEVICE_NOT_ACTIVE", "Thiet bi chua duoc cap phat hoac da bi thu hoi");
        }
        device["allowed_ip_addresses"] = json::array({allowed_ip_address});
        write_json(devices_policy_file_, devices_policy);

        return {
            true,
            "DEVICE_IP_UPDATED",
            "Da cap nhat IP duoc phep cho thiet bi",
            device_id,
            "",
            device.value("trust_level", 0),
            device.value("location_id", ""),
            device.value("device_name", device_id),
            device.value("device_type", "unknown"),
            device.value("enrollment_profile", "manual")
        };
    } catch (const std::exception& error) {
        return failure("DEVICE_IP_UPDATE_ERROR", error.what());
    }
}

DeviceOperationResult DeviceManagementService::remove(
    const std::string& device_id
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!valid_device_id(device_id)) {
        return failure("INVALID_DEVICE_ID", "Device ID khong hop le");
    }

    try {
        json devices_policy = read_json(devices_policy_file_);
        if (!devices_policy.contains("devices") ||
            !devices_policy.at("devices").contains(device_id)) {
            return failure("DEVICE_NOT_FOUND", "Khong tim thay thiet bi trong policy");
        }

        const json device = devices_policy["devices"][device_id];
        devices_policy["devices"].erase(device_id);

        json credentials = {
            {"schema_version", 1},
            {"devices", json::object()}
        };
        if (fs::exists(credentials_file_)) {
            credentials = read_json(credentials_file_);
            if (credentials.contains("devices")) {
                credentials["devices"].erase(device_id);
            }
        }

        // Xoa gan ket cu the cua user voi Device ID cu.
        // Quyen "*" cua admin PoC van duoc giu nguyen.
        if (fs::exists(users_file_)) {
            json users_data = read_json(users_file_);
            if (users_data.contains("users") && users_data["users"].is_array()) {
                for (auto& user : users_data["users"]) {
                    if (!user.contains("allowed_device_ids") ||
                        !user["allowed_device_ids"].is_array()) {
                        continue;
                    }

                    json retained = json::array();
                    for (const auto& allowed_id : user["allowed_device_ids"]) {
                        if (allowed_id != device_id) {
                            retained.push_back(allowed_id);
                        }
                    }
                    user["allowed_device_ids"] = retained;
                }
                write_json(users_file_, users_data);
            }
        }

        write_json(credentials_file_, credentials);
        write_json(devices_policy_file_, devices_policy);

        std::error_code error;
        fs::remove(
            fs::path(device_environment_directory_) / (device_id + ".env"),
            error
        );

        return {
            true,
            "DEVICE_DELETED",
            "Da xoa vinh vien thiet bi khoi policy va thu hoi khoa dinh danh",
            device_id,
            "",
            device.value("trust_level", 0),
            device.value("location_id", ""),
            device.value("device_name", device_id),
            device.value("device_type", "unknown"),
            device.value("enrollment_profile", "manual")
        };
    } catch (const std::exception& error) {
        return failure("DEVICE_DELETION_ERROR", error.what());
    }
}

DeviceOperationResult DeviceManagementService::block(
    const std::string& device_id
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!valid_device_id(device_id)) {
        return failure("INVALID_DEVICE_ID", "Device ID khong hop le");
    }

    try {
        json devices_policy = read_json(devices_policy_file_);
        if (!devices_policy.contains("devices") ||
            !devices_policy.at("devices").contains(device_id)) {
            return failure("DEVICE_NOT_FOUND", "Khong tim thay thiet bi trong policy");
        }

        json& device = devices_policy["devices"][device_id];
        device["registered"] = false;
        device["lifecycle_status"] = "BLOCKED";

        json credentials = {{"schema_version", 1}, {"devices", json::object()}};
        if (fs::exists(credentials_file_)) {
            credentials = read_json(credentials_file_);
            if (credentials.contains("devices")) {
                credentials["devices"].erase(device_id);
            }
        }

        write_json(credentials_file_, credentials);
        write_json(devices_policy_file_, devices_policy);
        std::error_code error;
        fs::remove(
            fs::path(device_environment_directory_) / (device_id + ".env"),
            error
        );

        return {
            true,
            "DEVICE_BLOCKED",
            "Da chan thiet bi va vo hieu hoa khoa dinh danh",
            device_id,
            "",
            device.value("trust_level", 0),
            device.value("location_id", ""),
            device.value("device_name", device_id),
            device.value("device_type", "unknown"),
            device.value("enrollment_profile", "manual")
        };
    } catch (const std::exception& error) {
        return failure("DEVICE_BLOCK_ERROR", error.what());
    }
}
