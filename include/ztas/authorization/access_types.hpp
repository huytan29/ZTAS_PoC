
// auth_level = mức đảm bảo xác thực hiện tại, từ 1 đến 5
//location_id = vùng truy cập, ví dụ lab-network hoặc external-network
//rule_id = mã rule kiểu ZTAS-1001
// severity = mức cảnh báo để ghi audit/dashboard

#pragma once

#include <string>


// Thông tin người dùng lấy từ token đã được xác thực
struct AccessSubject{
    std::string username;
    std::string role;
    int auth_level = 1;
};

// Tài nguyên được bảo vệ trong hệ thống
struct ProtectedResource{
    std::string id;
    std::string sensitivity;
    int level = 1;
    std::string content;
};

//Dữ liệu mà chương trình sẽ gửit đến OPA để xin quyết định truy cập
struct AccessRequest{
    AccessSubject subject;
    std::string device_id;
    std::string location_id;
    bool device_key_verified = false;
    ProtectedResource resource;
    std::string action;
};

//Kết quả OPA trả về sau khi đánh giá quyết định truy cập
struct AccessDecision{
    bool policy_available = true;
    std::string effect = "DENY";

    std::string rule_id = "ZTAS-0000";
    std::string reason_code = "POLICY_NOT_MATCHED";
    std::string severity = "info";
    std::string policy_version = "unknown";

    int current_auth_level = 1;
    int required_auth_level = 1;

    std::string resource_id;

    bool is_permitted() const {
        return policy_available && effect == "PERMIT";
    }
};

//Ý nghĩa: 
// AccessRequest = ai truy cập + dùng thiết bị nào để truy cập
// AccessDecision = OPA cho phép, từ chối, hay yêu cầu MFA
/*
Ví dụ:
AccessRequest request{
    {"tan", "employee", 1},
    "macbook-lab-01",
    "lab-network",
    true,
    {"secret_document", "secret", 4, ""},
    "read"
};

Tan dang o cap xac thuc 1, dung macbook-lab-01 trong lab-network
de doc tai lieu secret cap 4. OPA se tra ve PERMIT, DENY hoac STEP_UP.
*/
