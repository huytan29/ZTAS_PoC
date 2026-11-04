#include "ztas/identity/mfa_service.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
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

std::string random_otp() {
    std::uint32_t value = 0;
    if (RAND_bytes(
            reinterpret_cast<unsigned char*>(&value),
            sizeof(value)
        ) != 1) {
        return "";
    }

    std::ostringstream output;
    output << std::setw(6) << std::setfill('0')
           << (100000 + (value % 900000));
    return output.str();
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
    bool expose_demo_code
) : signing_secret_(std::move(signing_secret)),
    expose_demo_code_(expose_demo_code) {}

MfaChallenge MfaService::issue_challenge(
    const AccessSubject& subject,
    int required_auth_level
) {
    const int target_level = std::clamp(required_auth_level, 2, 5);
    const std::string challenge_id = random_challenge_id();
    const std::string code = random_otp();
    const long long expires_at = current_epoch() + 120;

    if (challenge_id.empty() || code.empty()) {
        return {"", target_level, 0, std::nullopt};
    }

    const StoredChallenge stored{
        subject.username,
        target_level,
        expires_at,
        fingerprint(challenge_id, subject.username, code, signing_secret_)
    };

    {
        std::lock_guard<std::mutex> lock(mutex_);
        remove_expired_locked(current_epoch());
        challenges_[challenge_id] = stored;
    }

    return {
        challenge_id,
        target_level,
        expires_at,
        expose_demo_code_ ? std::optional<std::string>(code) : std::nullopt
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
        found->second.expires_at < now) {
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
    challenges_.erase(found);
    return granted_level;
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
