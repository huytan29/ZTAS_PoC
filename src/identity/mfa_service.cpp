#include "ztas/identity/mfa_service.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

long long current_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
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

std::string random_challenge_id() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        return "";
    }
    return hex_encode(bytes, sizeof(bytes));
}

std::string fingerprint(
    const std::string& challenge_id,
    const std::string& username,
    const std::string& code,
    const std::string& secret
) {
    const std::string material =
        challenge_id + ":" + username + ":" + code;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;

    HMAC(
        EVP_sha256(),
        secret.data(),
        static_cast<int>(secret.size()),
        reinterpret_cast<const unsigned char*>(material.data()),
        material.size(),
        digest,
        &digest_length
    );

    return std::string(
        reinterpret_cast<const char*>(digest),
        digest_length
    );
}

bool same_value(
    const std::string& left,
    const std::string& right
) {
    return left.size() == right.size() &&
        CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

} // namespace

MfaService::MfaService(
    std::string signing_secret,
    std::string device_locks_file
) : signing_secret_(std::move(signing_secret)),
    device_locks_file_(std::move(device_locks_file)) {
    std::lock_guard<std::mutex> lock(mutex_);
    load_device_locks_locked();
}

MfaChallenge MfaService::issue_challenge(
    const AccessSubject& subject,
    int required_auth_level,
    const std::string& device_id,
    const std::string& resource_id
) {
    const int target_level = std::clamp(required_auth_level, 2, 5);
    const long long requested_at = current_epoch();
    std::lock_guard<std::mutex> lock(mutex_);
    remove_expired_locked(requested_at);

    // Mot tai khoan chi co mot yeu cau ma trong suot phien. Neu nguoi dung
    // bam lai vao cung/khac tai lieu, tra ve yeu cau cu thay vi sinh ma moi.
    for (const auto& [existing_id, stored] : challenges_) {
        if (stored.username == subject.username) {
            return {
                existing_id,
                stored.required_auth_level,
                stored.expires_at,
                stored.code_ready,
                true,
                stored.code_used || stored.code_revoked
            };
        }
    }

    const std::string challenge_id = random_challenge_id();
    // Dong bo voi phien dang nhap 15 phut. Trong thoi gian nay, mot tai
    // khoan khong the sinh them yeu cau ma chi vi bam lai tai lieu.
    const long long expires_at = requested_at + 900;
    if (challenge_id.empty()) return {"", target_level, 0, false};

    challenges_[challenge_id] = StoredChallenge{
        subject.username,
        subject.role,
        device_id,
        resource_id,
        target_level,
        requested_at,
        expires_at,
        false,
        false,
        false,
        0,
        ""
    };

    return {
        challenge_id,
        target_level,
        expires_at,
        false
    };
}

bool MfaService::valid_admin_code(const std::string& code) {
    bool has_uppercase = false;
    bool has_special = false;
    for (const unsigned char character : code) {
        has_uppercase = has_uppercase || std::isupper(character);
        has_special = has_special ||
            (!std::isalnum(character) && !std::isspace(character));
    }
    return code.size() >= 6 && has_uppercase && has_special;
}

bool MfaService::issue_admin_code(
    const std::string& challenge_id,
    const std::string& code
) {
    if (!valid_admin_code(code)) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    const long long now = current_epoch();
    remove_expired_locked(now);
    const auto found = challenges_.find(challenge_id);
    if (found == challenges_.end() || found->second.code_used ||
        found->second.code_revoked) return false;

    found->second.code_fingerprint = fingerprint(
        challenge_id,
        found->second.username,
        code,
        signing_secret_
    );
    found->second.code_ready = true;
    return true;
}

std::vector<MfaApprovalRequest> MfaService::list_requests() {
    std::lock_guard<std::mutex> lock(mutex_);
    remove_expired_locked(current_epoch());
    std::vector<MfaApprovalRequest> requests;
    requests.reserve(challenges_.size());
    for (const auto& [challenge_id, stored] : challenges_) {
        requests.push_back({
            challenge_id, stored.username, stored.role, stored.device_id,
            stored.resource_id, stored.required_auth_level,
            stored.requested_at, stored.expires_at, stored.code_ready,
            stored.code_used, stored.code_revoked
        });
    }
    std::sort(requests.begin(), requests.end(), [](const auto& left, const auto& right) {
        return left.requested_at > right.requested_at;
    });
    return requests;
}

std::optional<MfaApprovalRequest> MfaService::request_status(
    const AccessSubject& subject,
    const std::string& challenge_id
) {
    std::lock_guard<std::mutex> lock(mutex_);
    remove_expired_locked(current_epoch());
    const auto found = challenges_.find(challenge_id);
    if (found == challenges_.end() || found->second.username != subject.username) {
        return std::nullopt;
    }
    const auto& stored = found->second;
    return MfaApprovalRequest{
        challenge_id, stored.username, stored.role, stored.device_id,
        stored.resource_id, stored.required_auth_level,
        stored.requested_at, stored.expires_at, stored.code_ready,
        stored.code_used, stored.code_revoked
    };
}

MfaVerificationResult MfaService::verify_challenge(
    const AccessSubject& subject,
    const std::string& challenge_id,
    const std::string& code
) {
    std::lock_guard<std::mutex> lock(mutex_);
    const long long now = current_epoch();
    remove_expired_locked(now);

    const auto found = challenges_.find(challenge_id);
    if (found == challenges_.end() ||
        found->second.username != subject.username ||
        found->second.expires_at < now ||
        !found->second.code_ready || found->second.code_used ||
        found->second.code_revoked) {
        return {};
    }

    const std::string device_id = found->second.device_id;
    if (device_locks_.find(device_id) != device_locks_.end()) {
        return {false, true, 0, 0, device_id};
    }

    const std::string received = fingerprint(
        challenge_id,
        subject.username,
        code,
        signing_secret_
    );

    if (!same_value(received, found->second.code_fingerprint)) {
        ++found->second.failed_attempts;
        const int remaining_attempts = std::max(0, 3 - found->second.failed_attempts);
        if (found->second.failed_attempts >= 3) {
            device_locks_[device_id] = {
                device_id,
                subject.username,
                now,
                found->second.failed_attempts
            };
            // Huy tat ca challenge tren thiet bi de ma cu khong the duoc
            // dung lai sau khi admin go khoa.
            for (auto& [_, stored] : challenges_) {
                if (stored.device_id == device_id) stored.code_revoked = true;
            }
            save_device_locks_locked();
            return {false, true, 0, 0, device_id};
        }
        return {false, false, 0, remaining_attempts, device_id};
    }

    const int granted_level = found->second.required_auth_level;
    found->second.code_used = true;
    return {true, false, granted_level, 3, device_id};
}

void MfaService::clear_user_session(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iterator = challenges_.begin(); iterator != challenges_.end();) {
        if (iterator->second.username == username) {
            iterator = challenges_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

bool MfaService::revoke_challenge(const std::string& challenge_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    remove_expired_locked(current_epoch());
    const auto found = challenges_.find(challenge_id);
    if (found == challenges_.end() || found->second.code_revoked) return false;
    found->second.code_revoked = true;
    return true;
}

bool MfaService::is_challenge_active(
    const std::string& challenge_id,
    const std::string& username
) {
    std::lock_guard<std::mutex> lock(mutex_);
    remove_expired_locked(current_epoch());
    const auto found = challenges_.find(challenge_id);
    return found != challenges_.end() &&
        found->second.username == username &&
        found->second.code_used && !found->second.code_revoked &&
        device_locks_.find(found->second.device_id) == device_locks_.end();
}

bool MfaService::is_device_locked(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return device_locks_.find(device_id) != device_locks_.end();
}

std::vector<MfaDeviceLock> MfaService::list_device_locks() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MfaDeviceLock> locks;
    locks.reserve(device_locks_.size());
    for (const auto& [_, value] : device_locks_) locks.push_back(value);
    std::sort(locks.begin(), locks.end(), [](const auto& left, const auto& right) {
        return left.locked_at > right.locked_at;
    });
    return locks;
}

bool MfaService::unlock_device(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (device_locks_.erase(device_id) == 0) return false;
    // Bat buoc tao challenge moi sau khi admin go khoa; ma cu khong duoc
    // phep tiep tuc dung du chi biet ma.
    for (auto iterator = challenges_.begin(); iterator != challenges_.end();) {
        if (iterator->second.device_id == device_id) {
            iterator = challenges_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    return save_device_locks_locked();
}

void MfaService::remove_expired_locked(long long now) {
    for (auto iterator = challenges_.begin();
         iterator != challenges_.end();) {
        if (iterator->second.expires_at < now) {
            iterator = challenges_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

void MfaService::load_device_locks_locked() {
    device_locks_.clear();
    if (device_locks_file_.empty() || !fs::exists(device_locks_file_)) return;
    try {
        std::ifstream file(device_locks_file_);
        const json stored = json::parse(file);
        for (const auto& item : stored.value("locks", json::array())) {
            const std::string device_id = item.value("device_id", "");
            if (device_id.empty()) continue;
            device_locks_[device_id] = {
                device_id,
                item.value("username", ""),
                item.value("locked_at", 0LL),
                item.value("failed_attempts", 3)
            };
        }
    } catch (const std::exception&) {
        // Tep lock loi duoc coi la su co van hanh va can duoc kiem tra trong
        // audit/backup khi trien khai that.
    }
}

bool MfaService::save_device_locks_locked() const {
    if (device_locks_file_.empty()) return false;
    try {
        const fs::path path(device_locks_file_);
        fs::create_directories(path.parent_path());
        json stored = {{"schema_version", 1}, {"locks", json::array()}};
        for (const auto& [_, value] : device_locks_) {
            stored["locks"].push_back({
                {"device_id", value.device_id},
                {"username", value.username},
                {"locked_at", value.locked_at},
                {"failed_attempts", value.failed_attempts}
            });
        }
        const fs::path temporary = path.string() + ".tmp";
        {
            std::ofstream file(temporary);
            if (!file) return false;
            file << stored.dump(2) << '\n';
        }
        std::error_code error;
        fs::rename(temporary, path, error);
        if (error) {
            fs::remove(path, error);
            error.clear();
            fs::rename(temporary, path, error);
        }
        return !error;
    } catch (const std::exception&) {
        return false;
    }
}
