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

struct UserProvisioningResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
    std::string role;
};

struct UserDeletionResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
};

struct DeviceAssignmentResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
    std::string device_id;
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

    // Chi duoc goi tu API da xac thuc admin. Mat khau khoi tao cua tai khoan
    // PoC moi la ptit@123 va chi hash PBKDF2 duoc luu trong users.json.
    UserProvisioningResult create_user(
        const std::string& username,
        const std::string& role
    ) const;

    // Xoa vinh vien tai khoan va vo hieu hoa ngay token cua tai khoan do.
    // Khong cho phep tu xoa admin dang dang nhap hoac admin cuoi cung.
    UserDeletionResult delete_user(
        const std::string& username,
        const std::string& actor_username
    ) const;

    // Gan/go bo lien ket mot tai khoan voi mot thiet bi da duoc he thong
    // chap thuan. OPA van tu quyet dinh quyen theo role va policy.
    DeviceAssignmentResult assign_device(
        const std::string& username,
        const std::string& device_id
    ) const;

    DeviceAssignmentResult unassign_device(
        const std::string& username,
        const std::string& device_id
    ) const;

private:
    std::string users_file_;
    std::string token_secret_;
    mutable std::mutex mutex_;
};
