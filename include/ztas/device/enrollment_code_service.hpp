#pragma once

#include <mutex>
#include <string>

struct EnrollmentProfile {
    std::string id;
    std::string label;
    int trust_level = 0;
    std::string location_id;
};

struct EnrollmentCodeIssueResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string enrollment_code;
    EnrollmentProfile profile;
    std::string assigned_username;
    long long expires_at = 0;
};

struct EnrollmentCodeConsumeResult {
    bool success = false;
    std::string code;
    std::string message;
    EnrollmentProfile profile;
    std::string assigned_username;
};

// Ma dang ky co entropy cao, chi dung mot lan va chi luu hash tren server.
// Ma xac nhan quyen gui yeu cau; admin van phai duyet cap Device Key.
class EnrollmentCodeService {
public:
    explicit EnrollmentCodeService(std::string code_store_file);

    EnrollmentCodeIssueResult issue(
        const std::string& profile_id,
        const std::string& assigned_username,
        int lifetime_seconds = 600
    ) const;

    EnrollmentCodeConsumeResult consume(
        const std::string& enrollment_code
    ) const;

    static const EnrollmentProfile* find_profile(
        const std::string& profile_id
    );

private:
    std::string code_store_file_;
    mutable std::mutex mutex_;
};
