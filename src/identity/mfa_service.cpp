#include "ztas/identity/mfa_service.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <utility>

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

MfaService::MfaService(std::string signing_secret)
    : signing_secret_(std::move(signing_secret)) {}

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

std::optional<int> MfaService::verify_challenge(
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
        return std::nullopt;
    }

    const std::string received = fingerprint(
        challenge_id,
        subject.username,
        code,
        signing_secret_
    );

    if (!same_value(received, found->second.code_fingerprint)) {
        return std::nullopt;
    }

    const int granted_level = found->second.required_auth_level;
    found->second.code_used = true;
    return granted_level;
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
        found->second.code_used && !found->second.code_revoked;
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
