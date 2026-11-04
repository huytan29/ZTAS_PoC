#pragma once

#include "ztas/authorization/access_types.hpp"

#include <mutex>
#include <optional>
#include <string>

struct PasswordSetupResult {
    bool success = false;
    std::string code;
    std::string message;
};

class AuthService {
public:
    AuthService(
        std::string users_file,
        std::string token_secret
    );

    std::optional<AccessSubject> authenticate(
        const std::string& username,
        const std::string& password
    ) const;

    std::string issue_token(
        const AccessSubject& subject
    ) const;

    std::optional<AccessSubject> verify_token(
        const std::string& token
    ) const;

    bool admin_password_setup_required() const;

    PasswordSetupResult set_initial_admin_password(
        const std::string& password
    ) const;

private:
    std::string users_file_;
    std::string token_secret_;
    mutable std::mutex mutex_;
};
