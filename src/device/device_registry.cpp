#include "ztas/device/device_registry.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using json = nlohmann::json;

namespace {

std::vector<std::string> split(
    const std::string& value,
    char delimiter
) {
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string item;

    while (std::getline(stream, item, delimiter)) {
        parts.push_back(item);
    }

    return parts;
}

std::optional<std::vector<unsigned char>> hex_decode(
    const std::string& value
) {
    if (value.size() % 2 != 0) {
        return std::nullopt;
    }

    std::vector<unsigned char> bytes;

    try {
        for (std::size_t index = 0;
             index < value.size();
             index += 2) {
            bytes.push_back(static_cast<unsigned char>(
                std::stoul(value.substr(index, 2), nullptr, 16)
            ));
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }

    return bytes;
}

std::string hex_encode(
    const unsigned char* input,
    std::size_t length
) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);

    for (std::size_t index = 0; index < length; ++index) {
        output.push_back(digits[(input[index] >> 4) & 0x0f]);
        output.push_back(digits[input[index] & 0x0f]);
    }

    return output;
}

bool verify_secret(
    const std::string& secret,
    const std::string& stored_hash
) {
    const auto parts = split(stored_hash, '$');

    if (parts.size() != 4 || parts[0] != "pbkdf2_sha256") {
        return false;
    }

    const auto salt = hex_decode(parts[2]);
    if (!salt.has_value()) {
        return false;
    }

    int iterations = 0;
    try {
        iterations = std::stoi(parts[1]);
    } catch (const std::exception&) {
        return false;
    }

    if (iterations < 100000) {
        return false;
    }

    unsigned char derived[32];
    const int success = PKCS5_PBKDF2_HMAC(
        secret.c_str(),
        static_cast<int>(secret.size()),
        salt->data(),
        static_cast<int>(salt->size()),
        iterations,
        EVP_sha256(),
        sizeof(derived),
        derived
    );

    if (success != 1) {
        return false;
    }

    const std::string candidate = hex_encode(derived, sizeof(derived));

    return candidate.size() == parts[3].size() &&
        CRYPTO_memcmp(
            candidate.data(),
            parts[3].data(),
            candidate.size()
        ) == 0;
}

} // namespace

DeviceRegistry::DeviceRegistry(
    std::string credentials_file,
    std::string devices_policy_file
) : credentials_file_(std::move(credentials_file)),
    devices_policy_file_(std::move(devices_policy_file)) {}

bool DeviceRegistry::verify(
    const std::string& device_id,
    const std::string& device_key
) const {
    if (device_id.empty() || device_key.empty()) {
        return false;
    }

    try {
        std::ifstream file(credentials_file_);
        const json credentials = json::parse(file);
        const auto& device = credentials.at("devices").at(device_id);

        return device.value("active", false) &&
            verify_secret(device_key, device.value("key_hash", ""));
    } catch (const std::exception&) {
        return false;
    }
}

bool DeviceRegistry::verify_source_ip(
    const std::string& device_id,
    const std::string& source_ip
) const {
    if (device_id.empty() || source_ip.empty() || source_ip == "unknown") {
        return false;
    }

    try {
        std::ifstream file(devices_policy_file_);
        const json policy = json::parse(file);
        const auto& addresses = policy.at("devices").at(device_id)
            .at("allowed_ip_addresses");
        if (!addresses.is_array()) {
            return false;
        }
        for (const auto& address : addresses) {
            if (address.is_string() && address.get<std::string>() == source_ip) {
                return true;
            }
        }
    } catch (const std::exception&) {
        return false;
    }

    return false;
}

std::optional<ReaderDeviceContext> DeviceRegistry::resolve_reader_context(
    const std::vector<std::string>& allowed_device_ids,
    const std::string& source_ip
) const {
    if (source_ip.empty() || source_ip == "unknown") return std::nullopt;

    try {
        std::ifstream file(devices_policy_file_);
        const json policy = json::parse(file);
        const auto& devices = policy.at("devices");
        const bool global_scope = std::find(
            allowed_device_ids.begin(), allowed_device_ids.end(), "*"
        ) != allowed_device_ids.end();

        std::optional<ReaderDeviceContext> ip_matched;
        std::vector<ReaderDeviceContext> assigned_devices;
        for (auto iterator = devices.begin(); iterator != devices.end(); ++iterator) {
            const std::string device_id = iterator.key();
            const json& device = iterator.value();
            const bool assigned = global_scope || std::find(
                allowed_device_ids.begin(), allowed_device_ids.end(), device_id
            ) != allowed_device_ids.end();
            const bool active = device.value("registered", false) &&
                device.value("lifecycle_status", "ACTIVE") == "ACTIVE";
            if (!assigned || !active) {
                continue;
            }
            const ReaderDeviceContext candidate{
                device_id,
                device.value("location_id", "unknown")
            };
            assigned_devices.push_back(candidate);
            if (verify_source_ip(device_id, source_ip)) {
                if (ip_matched.has_value()) return std::nullopt;
                ip_matched = candidate;
            }
        }
        if (ip_matched.has_value()) return ip_matched;

        // Sau khi admin da duyet thiet bi va gan duy nhat mot tai khoan vao
        // no, giao dien web chi can dung phien dang nhap cua tai khoan do.
        // IP van duoc ghi audit; ket noi co nhieu thiet bi phu hop thi khong
        // tu y chon, tru truong hop admin co pham vi toan cuc.
        if (assigned_devices.size() == 1) return assigned_devices.front();
        if (global_scope && !assigned_devices.empty()) {
            return assigned_devices.front();
        }
        return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}
