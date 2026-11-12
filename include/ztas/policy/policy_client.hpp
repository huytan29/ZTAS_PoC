/*
Policy Client: Lớp duy nhất đuọcw phép gọi OPA
Nó nhận AccessRequest, chuyeển thành JSON, gửi HTTP POST sang OPA và đổi JSOn trẻ về thành Access Decision

*/

#pragma once

#include "ztas/authorization/access_types.hpp"

#include <optional>
#include <string>

class PolicyClient {
public:
    explicit PolicyClient(std::string opa_host);

    std::optional<AccessDecision> decide(
        const AccessRequest& request
    ) const;

    // Docker Desktop tren Windows khong luon phat hien thay doi bind mount
    // ngay lap tuc. Day ban ghi devices moi vao OPA qua Data API sau moi
    // thao tac cap phat/thu hoi de policy khong dung du lieu cu.
    bool sync_devices_policy(const std::string& devices_policy_file) const;

private:
    std::string opa_host_;
};
/*
Điểm cần hiểu:
- opa_host_: tên hoặc địa chỉ OPA, ví dụ opa trong Docker hoặc 127.0.0.1 khi chạy local.
- std::optional: có thể trả về quyết định, hoặc không có kết quả nếu OPA lỗi/tắt.
- decide() không tự quyết định quyền; chỉ hỏi OPA.
*/

