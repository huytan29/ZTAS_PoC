#include "ztas/identity/auth_service.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

using json = nlohmann::json;
namespace fs = std::filesystem;

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

std::string hex_encode(
    const unsigned char* input,
    std::size_t length
) {
    static constexpr char digits[] =
        "0123456789abcdef";

    std::string output;
    output.reserve(length * 2);

    for (std::size_t index = 0; index < length; ++index) {
        output.push_back(
            digits[(input[index] >> 4) & 0x0f]
        );
        output.push_back(
            digits[input[index] & 0x0f]
        );
    }

    return output;
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
            bytes.push_back(
                static_cast<unsigned char>(
                    std::stoul(
                        value.substr(index, 2),
                        nullptr,
                        16
                    )
                )
            );
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }

    return bytes;
}

bool verify_secret(
    const std::string& secret,
    const std::string& stored_hash
) {
    const auto parts = split(stored_hash, '$');

    if (parts.size() != 4 ||
        parts[0] != "pbkdf2_sha256") {
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

    const std::string candidate =
        hex_encode(derived, sizeof(derived));

    if (candidate.size() != parts[3].size()) {
        return false;
    }

    return CRYPTO_memcmp(
        candidate.data(),
        parts[3].data(),
        candidate.size()
    ) == 0;
}

bool is_password_hash_configured(const std::string& stored_hash) {
    const auto parts = split(stored_hash, '$');
    return parts.size() == 4 &&
        parts[0] == "pbkdf2_sha256" &&
        !parts[1].empty() &&
        !parts[2].empty() &&
        !parts[3].empty();
}

std::string create_password_hash(const std::string& password) {
    constexpr int iterations = 200000;
    unsigned char salt[16];
    unsigned char derived[32];

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            salt,
            sizeof(salt),
            iterations,
            EVP_sha256(),
            sizeof(derived),
            derived
        ) != 1) {
        throw std::runtime_error("Khong the tao password hash");
    }

    return "pbkdf2_sha256$" + std::to_string(iterations) + "$" +
        hex_encode(salt, sizeof(salt)) + "$" +
        hex_encode(derived, sizeof(derived));
}

bool valid_username(const std::string& username) {
    if (username.size() < 3 || username.size() > 32) {
        return false;
    }

    for (const char character : username) {
        if (!std::islower(static_cast<unsigned char>(character)) &&
            !std::isdigit(static_cast<unsigned char>(character)) &&
            character != '-' && character != '_' && character != '.') {
            return false;
        }
    }

    return username.front() != '-' && username.front() != '_' &&
        username.front() != '.';
}

bool valid_role(const std::string& role) {
    static const std::vector<std::string> allowed_roles = {
        "admin", "employee", "manager", "engineer", "guest"
    };
    return std::find(allowed_roles.begin(), allowed_roles.end(), role) !=
        allowed_roles.end();
}

void write_users_data(const std::string& users_file, const json& users_data) {
    const fs::path path(users_file);
    const fs::path temporary = path.string() + ".tmp";

    {
        std::ofstream file(temporary);
        if (!file) {
            throw std::runtime_error("Khong ghi duoc users.json");
        }
        file << users_data.dump(2) << '\n';
    }

    std::error_code error;
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
    }

    if (error) {
        throw std::runtime_error("Khong thay the duoc users.json");
    }
}

std::string base64url_encode(
    const std::string& input
) {
    std::string encoded(
        4 * ((input.size() + 2) / 3),
        '\0'
    );

    const int size = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()),
        reinterpret_cast<const unsigned char*>(
            input.data()
        ),
        static_cast<int>(input.size())
    );

    encoded.resize(size);

    std::replace(
        encoded.begin(), encoded.end(), '+', '-'
    );
    std::replace(
        encoded.begin(), encoded.end(), '/', '_'
    );

    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }

    return encoded;
}

std::optional<std::string> base64url_decode(
    const std::string& input
) {
    std::string encoded = input;

    std::replace(
        encoded.begin(), encoded.end(), '-', '+'
    );
    std::replace(
        encoded.begin(), encoded.end(), '_', '/'
    );

    while (encoded.size() % 4 != 0) {
        encoded.push_back('=');
    }

    std::string decoded(
        3 * (encoded.size() / 4),
        '\0'
    );

    const int size = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(decoded.data()),
        reinterpret_cast<const unsigned char*>(
            encoded.data()
        ),
        static_cast<int>(encoded.size())
    );

    if (size < 0) {
        return std::nullopt;
    }

    int padding = 0;

    if (!encoded.empty() && encoded.back() == '=') {
        ++padding;
    }

    if (encoded.size() > 1 &&
        encoded[encoded.size() - 2] == '=') {
        ++padding;
    }

    decoded.resize(size - padding);
    return decoded;
}

std::string sign(
    const std::string& value,
    const std::string& secret
) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;

    HMAC(
        EVP_sha256(),
        secret.data(),
        static_cast<int>(secret.size()),
        reinterpret_cast<const unsigned char*>(
            value.data()
        ),
        value.size(),
        digest,
        &digest_length
    );

    return base64url_encode(
        std::string(
            reinterpret_cast<const char*>(digest),
            digest_length
        )
    );
}

long long current_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace

AuthService::AuthService(
    std::string users_file,
    std::string token_secret
) : users_file_(std::move(users_file)),
    token_secret_(std::move(token_secret)) {}

std::optional<AccessSubject> AuthService::authenticate(
    const std::string& username,
    const std::string& password
) const {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ifstream file(users_file_);
        const json users_data = json::parse(file);
        const long long now = current_epoch();

        for (const auto& user : users_data.at("users")) {
            if (user.value("username", "") == username &&
                verify_secret(
                    password,
                    user.value("password_hash", "")
                )) {
                const long long fixed_expires_at =
                    user.value("expires_at", 0LL);

                if (fixed_expires_at > 0 && fixed_expires_at <= now) {
                    return std::nullopt;
                }

                long long effective_expires_at = fixed_expires_at;
                const int temporary_session_minutes =
                    user.value("temporary_session_minutes", 0);

                if (temporary_session_minutes > 0) {
                    const long long temporary_expiry = now +
                        static_cast<long long>(temporary_session_minutes) * 60;
                    effective_expires_at = fixed_expires_at > 0
                        ? std::min(fixed_expires_at, temporary_expiry)
                        : temporary_expiry;
                }

                return AccessSubject{
                    username,
                    user.value("role", ""),
                    1,
                    user.value(
                        "allowed_device_ids",
                        std::vector<std::string>{}
                    ),
                    effective_expires_at
                };
            }
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }

    return std::nullopt;
}

bool AuthService::admin_password_setup_required() const {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        std::ifstream file(users_file_);
        const json users_data = json::parse(file);

        for (const auto& user : users_data.at("users")) {
            if (user.value("username", "") == "admin" &&
                user.value("role", "") == "admin") {
                return !is_password_hash_configured(
                    user.value("password_hash", "")
                );
            }
        }
    } catch (const std::exception&) {
        return false;
    }

    return false;
}

PasswordSetupResult AuthService::set_initial_admin_password(
    const std::string& password
) const {
    if (password.empty()) {
        return {
            false,
            "PASSWORD_REQUIRED",
            "Mat khau khong duoc de trong"
        };
    }

    std::lock_guard<std::mutex> lock(mutex_);

    try {
        std::ifstream file(users_file_);
        json users_data = json::parse(file);
        // Windows khong cho thay the tep dang mo. Dong handle doc truoc khi
        // write_users_data() doi ten tep tam de cap nhat du lieu atomically.
        file.close();

        for (auto& user : users_data.at("users")) {
            if (user.value("username", "") != "admin" ||
                user.value("role", "") != "admin") {
                continue;
            }

            if (is_password_hash_configured(
                    user.value("password_hash", "")
                )) {
                return {
                    false,
                    "ADMIN_PASSWORD_ALREADY_CONFIGURED",
                    "Mat khau admin da duoc thiet lap"
                };
            }

            user["password_hash"] = create_password_hash(password);
            write_users_data(users_file_, users_data);

            return {
                true,
                "ADMIN_PASSWORD_CONFIGURED",
                "Da thiet lap mat khau admin"
            };
        }
    } catch (const std::exception& error) {
        return {
            false,
            "ADMIN_PASSWORD_SETUP_ERROR",
            error.what()
        };
    }

    return {
        false,
        "ADMIN_USER_NOT_FOUND",
        "Khong tim thay user admin"
    };
}

UserProvisioningResult AuthService::create_user(
    const std::string& username,
    const std::string& role
) const {
    if (!valid_username(username)) {
        return {
            false,
            "INVALID_USERNAME",
            "Username gom 3-32 ky tu thuong, so, dau gach ngang, gach duoi hoac cham",
            "",
            ""
        };
    }

    if (!valid_role(role)) {
        return {
            false,
            "INVALID_ROLE",
            "Role khong nam trong danh sach duoc phep",
            "",
            ""
        };
    }

    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::ifstream file(users_file_);
        json users_data = json::parse(file);
        // Can dong handle doc truoc khi thay the users.json tren Windows.
        file.close();
        if (!users_data.contains("users") || !users_data["users"].is_array()) {
            return {false, "INVALID_USERS_STORE", "Kho tai khoan khong dung dinh dang", "", ""};
        }

        for (const auto& user : users_data["users"]) {
            if (user.value("username", "") == username) {
                return {
                    false,
                    "USERNAME_ALREADY_EXISTS",
                    "Username nay da ton tai",
                    "",
                    ""
                };
            }
        }

        json user = {
            {"username", username},
            {"role", role},
            {"password_hash", create_password_hash("ptit@123")},
            {"allowed_device_ids", json::array()},
            {"expires_at", 0}
        };

        // Tai khoan guest la phien tam thoi trong PoC, con cac role khac
        // can duoc admin gan thiet bi truoc khi truy cap du lieu.
        if (role == "guest") {
            user["temporary_session_minutes"] = 60;
        }

        users_data["users"].push_back(std::move(user));
        write_users_data(users_file_, users_data);

        return {
            true,
            "USER_CREATED",
            "Da tao tai khoan voi mat khau khoi tao ptit@123",
            username,
            role
        };
    } catch (const std::exception& error) {
        return {
            false,
            "USER_CREATION_ERROR",
            error.what(),
            "",
            ""
        };
    }
}

UserDeletionResult AuthService::delete_user(
    const std::string& username,
    const std::string& actor_username
) const {
    if (username.empty()) {
        return {false, "USERNAME_REQUIRED", "Can chi dinh tai khoan can xoa", ""};
    }

    if (username == actor_username) {
        return {
            false,
            "SELF_DELETION_FORBIDDEN",
            "Khong the xoa tai khoan admin dang dang nhap",
            ""
        };
    }

    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::ifstream file(users_file_);
        json users_data = json::parse(file);
        // Can dong handle doc truoc khi thay the users.json tren Windows.
        file.close();
        if (!users_data.contains("users") || !users_data["users"].is_array()) {
            return {false, "INVALID_USERS_STORE", "Kho tai khoan khong dung dinh dang", ""};
        }

        auto& users = users_data["users"];
        const auto target = std::find_if(
            users.begin(), users.end(),
            [&username](const json& user) {
                return user.value("username", "") == username;
            }
        );

        if (target == users.end()) {
            return {false, "USER_NOT_FOUND", "Khong tim thay tai khoan", ""};
        }

        if (target->value("role", "") == "admin") {
            const auto admin_count = std::count_if(
                users.begin(), users.end(),
                [](const json& user) {
                    return user.value("role", "") == "admin";
                }
            );
            if (admin_count <= 1) {
                return {
                    false,
                    "LAST_ADMIN_PROTECTED",
                    "Khong the xoa tai khoan admin cuoi cung",
                    ""
                };
            }
        }

        users.erase(target);
        write_users_data(users_file_, users_data);
        return {true, "USER_DELETED", "Da xoa vinh vien tai khoan", username};
    } catch (const std::exception& error) {
        return {false, "USER_DELETION_ERROR", error.what(), ""};
    }
}

namespace {

DeviceAssignmentResult update_device_assignment(
    const std::string& users_file,
    std::mutex& mutex,
    const std::string& username,
    const std::string& device_id,
    bool assign
) {
    if (username.empty() || device_id.empty()) {
        return {
            false,
            "ASSIGNMENT_CONTEXT_REQUIRED",
            "Can chi dinh tai khoan va thiet bi",
            "",
            ""
        };
    }

    std::lock_guard<std::mutex> lock(mutex);
    try {
        std::ifstream file(users_file);
        json users_data = json::parse(file);
        file.close();
        if (!users_data.contains("users") || !users_data["users"].is_array()) {
            return {false, "INVALID_USERS_STORE", "Kho tai khoan khong dung dinh dang", "", ""};
        }

        for (auto& user : users_data["users"]) {
            if (user.value("username", "") != username) {
                continue;
            }

            json& allowed = user["allowed_device_ids"];
            if (!allowed.is_array()) {
                allowed = json::array();
            }

            const auto global_scope = std::find(
                allowed.begin(), allowed.end(), "*"
            );
            if (global_scope != allowed.end()) {
                return {
                    false,
                    "GLOBAL_DEVICE_SCOPE_PROTECTED",
                    "Tai khoan nay co pham vi quan tri toan he thong",
                    username,
                    device_id
                };
            }

            const auto existing = std::find(
                allowed.begin(), allowed.end(), device_id
            );
            if (assign) {
                if (existing != allowed.end()) {
                    return {
                        false,
                        "DEVICE_ALREADY_ASSIGNED",
                        "Tai khoan da duoc gan voi thiet bi nay",
                        username,
                        device_id
                    };
                }
                allowed.push_back(device_id);
            } else {
                if (existing == allowed.end()) {
                    return {
                        false,
                        "DEVICE_NOT_ASSIGNED",
                        "Tai khoan chua duoc gan voi thiet bi nay",
                        username,
                        device_id
                    };
                }
                allowed.erase(existing);
            }

            write_users_data(users_file, users_data);
            return {
                true,
                assign ? "USER_DEVICE_ASSIGNED" : "USER_DEVICE_UNASSIGNED",
                assign ? "Da gan tai khoan voi thiet bi" : "Da go gan ket tai khoan va thiet bi",
                username,
                device_id
            };
        }
    } catch (const std::exception& error) {
        return {false, "DEVICE_ASSIGNMENT_ERROR", error.what(), "", ""};
    }

    return {false, "USER_NOT_FOUND", "Khong tim thay tai khoan", "", ""};
}

} // namespace

DeviceAssignmentResult AuthService::assign_device(
    const std::string& username,
    const std::string& device_id
) const {
    return update_device_assignment(
        users_file_, mutex_, username, device_id, true
    );
}

DeviceAssignmentResult AuthService::unassign_device(
    const std::string& username,
    const std::string& device_id
) const {
    return update_device_assignment(
        users_file_, mutex_, username, device_id, false
    );
}

std::string AuthService::issue_token(
    const AccessSubject& subject
) const {
    const long long now = current_epoch();
    const long long token_expiry = subject.account_expires_at > 0
        ? std::min(now + 900, subject.account_expires_at)
        : now + 900;

    json payload = {
        {"sub", subject.username},
        {"role", subject.role},
        {"auth_level", subject.auth_level},
        {"allowed_device_ids", subject.allowed_device_ids},
        {"account_expires_at", subject.account_expires_at},
        {"iat", now},
        {"exp", token_expiry}
    };

    if (!subject.reader_device_id.empty() &&
        !subject.reader_location_id.empty()) {
        payload["reader_device_id"] = subject.reader_device_id;
        payload["reader_location_id"] = subject.reader_location_id;
    }

    const std::string encoded_payload =
        base64url_encode(payload.dump());

    return encoded_payload + "." +
        sign(encoded_payload, token_secret_);
}

std::string AuthService::issue_reader_token(
    const AccessSubject& subject,
    const std::string& device_id,
    const std::string& location_id
) const {
    AccessSubject reader_subject = subject;
    reader_subject.reader_device_id = device_id;
    reader_subject.reader_location_id = location_id;
    return issue_token(reader_subject);
}

std::optional<AccessSubject> AuthService::verify_token(
    const std::string& token
) const {
    const auto separator = token.rfind('.');

    if (separator == std::string::npos) {
        return std::nullopt;
    }

    const std::string encoded_payload =
        token.substr(0, separator);

    const std::string signature =
        token.substr(separator + 1);

    const std::string expected_signature =
        sign(encoded_payload, token_secret_);

    if (signature.size() != expected_signature.size() ||
        CRYPTO_memcmp(
            signature.data(),
            expected_signature.data(),
            signature.size()
        ) != 0) {
        return std::nullopt;
    }

    const auto decoded =
        base64url_decode(encoded_payload);

    if (!decoded.has_value()) {
        return std::nullopt;
    }

    try {
        const json payload = json::parse(*decoded);

        const long long now = current_epoch();

        const int auth_level =
            payload.value("auth_level", 0);

        const long long account_expires_at =
            payload.value("account_expires_at", 0LL);

        if (payload.value("exp", 0LL) < now ||
            (account_expires_at > 0 && account_expires_at <= now) ||
            auth_level < 1 ||
            auth_level > 5) {
            return std::nullopt;
        }

        const std::string username =
            payload.value("sub", "");

        const std::string role =
            payload.value("role", "");

        if (username.empty() || role.empty()) {
            return std::nullopt;
        }

        // Token dung ky van phai tham chieu tai khoan con ton tai. Vi vay
        // xoa tai khoan co hieu luc ngay, thay vi cho token 15 phut het han.
        std::lock_guard<std::mutex> lock(mutex_);
        std::ifstream file(users_file_);
        const json users_data = json::parse(file);
        for (const auto& user : users_data.at("users")) {
            if (user.value("username", "") != username ||
                user.value("role", "") != role) {
                continue;
            }

            const long long configured_expiry =
                user.value("expires_at", 0LL);
            if (configured_expiry > 0 && configured_expiry <= now) {
                return std::nullopt;
            }

            return AccessSubject{
                username,
                role,
                auth_level,
                user.value(
                    "allowed_device_ids",
                    std::vector<std::string>{}
                ),
                account_expires_at,
                payload.value("reader_device_id", ""),
                payload.value("reader_location_id", "")
            };
        }

        return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

