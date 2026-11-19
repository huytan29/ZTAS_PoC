#pragma once

#include "ztas/authorization/access_types.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <vector>

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
    // Chi tra ve khi tao/cap lai; khong bao gio luu dang ro.
    std::string account_key;
};

struct AccountKeyIssueResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
    std::string account_key;
};

struct UserDeletionResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
};

struct UserPermissionUpdateResult {
    bool success = false;
    std::string code;
    std::string message;
    std::string username;
    std::vector<std::string> assigned_tasks;
    std::string task_description;
};

struct PasswordChangeResult {
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

    // Dung duy nhat trong luong may moi gui yeu cau ket noi. Ca mat khau va
    // Account Key deu phai dung; key chi duoc luu duoi dang PBKDF2 hash.
    std::optional<AccessSubject> authenticate_device_enrollment(
        const std::string& username,
        const std::string& password,
        const std::string& account_key
    ) const;

    // Kiem tra lai lien ket tai khoan-thiet bi khi admin duyet khoi phuc
    // Browser Proof. Khong yeu cau va khong lam lo Account Key.
    bool is_device_assigned_to_user(
        const std::string& username,
        const std::string& device_id
    ) const;

    std::string issue_token(
        const AccessSubject& subject
    ) const;

    std::string issue_reader_token(
        const AccessSubject& subject,
        const std::string& device_id,
        const std::string& location_id
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
        const std::string& role,
        const std::string& organization_unit = "unit-a",
        const std::vector<std::string>& assigned_tasks = {},
        const std::string& task_description = ""
    ) const;

    // Cap lai Account Key cho tai khoan co san va vo hieu hoa key cu ngay lap tuc.
    AccountKeyIssueResult issue_account_key(
        const std::string& username
    ) const;

    // Cap/thu hep pham vi tai lieu cua tai khoan. Pham vi khong the vuot qua
    // role va don vi cua tai khoan; dang xuat/dang nhap lai de ap dung token moi.
    UserPermissionUpdateResult update_document_permissions(
        const std::string& username,
        const std::vector<std::string>& assigned_tasks,
        const std::string& task_description = ""
    ) const;

    // Nguoi dung tu doi mat khau cua chinh minh; phai xac nhan mat khau cu.
    PasswordChangeResult change_own_password(
        const std::string& username,
        const std::string& current_password,
        const std::string& new_password
    ) const;

    // Admin chi dat lai tai khoan khach ve mat khau mac dinh ptit@123. Mat
    // khau cua admin chi co the duoc doi qua change_own_password().
    PasswordChangeResult reset_user_password_to_default(
        const std::string& username
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
