#pragma once

#include "ztas/authorization/access_types.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

struct MfaChallenge {
    std::string challenge_id;
    int required_auth_level = 2;
    long long expires_at = 0;

    // Chi co gia tri khi ZTAS_DEMO_MFA=true. Khong dung trong production.
    std::optional<std::string> demo_code;
};

class MfaService {
public:
    MfaService(
        std::string signing_secret,
        bool expose_demo_code
    );

    MfaChallenge issue_challenge(
        const AccessSubject& subject,
        int required_auth_level
    );

    std::optional<int> verify_challenge(
        const AccessSubject& subject,
        const std::string& challenge_id,
        const std::string& code
    );

private:
    struct StoredChallenge {
        std::string username;
        int required_auth_level = 2;
        long long expires_at = 0;
        std::string code_fingerprint;
    };

    std::string signing_secret_;
    bool expose_demo_code_ = false;
    std::mutex mutex_;
    std::unordered_map<std::string, StoredChallenge> challenges_;

    void remove_expired_locked(long long now);
};
