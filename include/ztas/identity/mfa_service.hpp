#pragma once

#include "ztas/authorization/access_types.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

struct MfaChallenge {
    std::string challenge_id;
    int required_auth_level = 2;
    long long expires_at = 0;
    bool code_ready = false;
};

struct MfaApprovalRequest {
    std::string challenge_id;
    std::string username;
    std::string role;
    std::string device_id;
    std::string resource_id;
    int required_auth_level = 2;
    long long requested_at = 0;
    long long expires_at = 0;
    bool code_ready = false;
};

class MfaService {
public:
    explicit MfaService(std::string signing_secret);

    MfaChallenge issue_challenge(
        const AccessSubject& subject,
        int required_auth_level,
        const std::string& device_id,
        const std::string& resource_id
    );

    // Mã chỉ được admin gán sau khi xem hàng chờ. Quy tắc: ít nhất sáu chữ
    // số, một chữ hoa và một ký tự đặc biệt.
    bool issue_admin_code(
        const std::string& challenge_id,
        const std::string& code
    );

    std::vector<MfaApprovalRequest> list_requests();

    std::optional<MfaApprovalRequest> request_status(
        const AccessSubject& subject,
        const std::string& challenge_id
    );

    std::optional<int> verify_challenge(
        const AccessSubject& subject,
        const std::string& challenge_id,
        const std::string& code
    );

private:
    struct StoredChallenge {
        std::string username;
        std::string role;
        std::string device_id;
        std::string resource_id;
        int required_auth_level = 2;
        long long requested_at = 0;
        long long expires_at = 0;
        bool code_ready = false;
        std::string code_fingerprint;
    };

    std::string signing_secret_;
    std::mutex mutex_;
    std::unordered_map<std::string, StoredChallenge> challenges_;

    static bool valid_admin_code(const std::string& code);
    void remove_expired_locked(long long now);
};
