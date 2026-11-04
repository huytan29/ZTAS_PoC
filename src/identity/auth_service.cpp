#include "ztas/identity/auth_service.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
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
        std::ifstream file(users_file_);
        const json users_data = json::parse(file);

        for (const auto& user : users_data.at("users")) {
            if (user.value("username", "") == username &&
                verify_secret(
                    password,
                    user.value("password_hash", "")
                )) {
                return AccessSubject{
                    username,
                    user.value("role", ""),
                    1
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

std::string AuthService::issue_token(
    const AccessSubject& subject
) const {
    const auto now =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now()
                .time_since_epoch()
        ).count();

    const json payload = {
        {"sub", subject.username},
        {"role", subject.role},
        {"auth_level", subject.auth_level},
        {"iat", now},
        {"exp", now + 900}
    };

    const std::string encoded_payload =
        base64url_encode(payload.dump());

    return encoded_payload + "." +
        sign(encoded_payload, token_secret_);
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

        const auto now =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now()
                    .time_since_epoch()
            ).count();

        const int auth_level =
            payload.value("auth_level", 0);

        if (payload.value("exp", 0LL) < now ||
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

        return AccessSubject{
            username,
            role,
            auth_level
        };
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

