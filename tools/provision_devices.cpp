#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

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

json read_json_file(const fs::path& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Khong mo duoc tep: " + path.string());
    }
    return json::parse(file);
}

void write_json_file(const fs::path& path, const json& value) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Khong ghi duoc tep: " + path.string());
    }
    file << value.dump(2) << '\n';
}

void write_device_environment(
    const fs::path& path,
    const std::string& device_id,
    const std::string& device_key,
    const std::string& location_id
) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Khong ghi duoc tep: " + path.string());
    }

    file << "# Tu dong sinh boi provision_devices. Khong dua tep nay len Git.\n"
         << "DEVICE_ID=" << device_id << '\n'
         << "DEVICE_KEY=" << device_key << '\n'
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

void append_audit_event(const fs::path& path, json event) {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    event["timestamp_epoch"] = now;
    std::ofstream file(path, std::ios::app);
    if (file) {
        file << event.dump() << '\n';
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr
            << "Dung: provision_devices <devices.json> "
            << "<device_credentials.json> <thu_muc_device_env>\n";
        return 1;
    }

    try {
        const fs::path policy_path = argv[1];
        const fs::path credentials_path = argv[2];
        const fs::path environment_directory = argv[3];
        const fs::path audit_path =
            credentials_path.parent_path() / "audit.jsonl";

        const json policy = read_json_file(policy_path);
        const auto& policy_devices = policy.at("devices");

        json credentials = {
            {"schema_version", 1},
            {"devices", json::object()}
        };

        if (fs::exists(credentials_path)) {
            credentials = read_json_file(credentials_path);
            if (!credentials.contains("devices")) {
                throw std::runtime_error("Credentials khong dung dinh dang");
            }
        }

        fs::create_directories(credentials_path.parent_path());
        fs::create_directories(environment_directory);

        append_audit_event(audit_path, {
            {"event_type", "DEVICE_PROVISION_STARTED"},
            {"policy_file", policy_path.string()}
        });

        int created = 0;
        int preserved = 0;

        for (auto iterator = policy_devices.begin();
             iterator != policy_devices.end();
             ++iterator) {
            const std::string device_id = iterator.key();
            const json& device = iterator.value();

            if (!device.value("registered", false)) {
                credentials["devices"].erase(device_id);
                append_audit_event(audit_path, {
                    {"event_type", "DEVICE_PROVISION_SKIPPED"},
                    {"device_id", device_id},
                    {"reason_code", "DEVICE_NOT_REGISTERED"}
                });
                std::cout << "[SKIPPED] " << device_id
                          << " - chua duoc dang ky\n";
                continue;
            }

            if (credentials["devices"].contains(device_id)) {
                ++preserved;
                append_audit_event(audit_path, {
                    {"event_type", "DEVICE_PROVISION_PRESERVED"},
                    {"device_id", device_id},
                    {"location_id", device.value("location_id", "")},
                    {"trust_level", device.value("trust_level", 0)}
                });
                std::cout << "[PRESERVED] " << device_id
                          << " - giu nguyen khoa\n";
                continue;
            }

            const std::string key = create_device_key();
            credentials["devices"][device_id] = {
                {"active", true},
                {"key_hash", hash_key(key)}
            };

            write_device_environment(
                environment_directory / (device_id + ".env"),
                device_id,
                key,
                device.value("location_id", "")
            );
            append_audit_event(audit_path, {
                {"event_type", "DEVICE_PROVISIONED"},
                {"device_id", device_id},
                {"location_id", device.value("location_id", "")},
                {"trust_level", device.value("trust_level", 0)}
            });
            std::cout << "[PROVISIONED] " << device_id
                      << " - trust level "
                      << device.value("trust_level", 0) << '\n';
            ++created;
        }

        write_json_file(credentials_path, credentials);
        append_audit_event(audit_path, {
            {"event_type", "DEVICE_PROVISION_FINISHED"},
            {"created", created},
            {"preserved", preserved}
        });

        std::cout << "Da cap moi " << created
                  << " thiet bi, giu nguyen " << preserved
                  << " thiet bi da co khoa.\n"
                  << "Credentials server: " << credentials_path << '\n'
                  << "Environment moi thiet bi: " << environment_directory
                  << '\n';
    } catch (const std::exception& error) {
        std::cerr << "Provisioning that bai: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
