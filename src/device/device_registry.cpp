#include "ztas/device/device_registry.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

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

DeviceRegistry::DeviceRegistry(std::string credentials_file)
    : credentials_file_(std::move(credentials_file)) {}

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
