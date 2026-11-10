#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <mutex>
#include <string>

struct AuditSaveResult {
    bool success = false;
    std::string code;
    std::string message;
};

class AuditLogger {
public:
    // Moi ngay mot file JSONL: <log_directory>/YYYY-MM-DD.jsonl
    explicit AuditLogger(std::string log_directory);

    void write(const nlohmann::json& event) const;

    nlohmann::json read_recent(
        std::size_t limit
    ) const;

    // Doc dung mot ngay, theo dinh dang YYYY-MM-DD.
    nlohmann::json read_day(
        const std::string& date,
        std::size_t limit
    ) const;

    // Luu snapshot rieng tai data/saved-logs. Cac ban nay khong bi retention
    // 5 ngay xoa va co the duoc tai ve tu giao dien.
    AuditSaveResult save_day(const std::string& date) const;

    // Xoa audit chua luu rieng sau 5 ngay lich. Goi luc khoi dong va sau moi
    // su kien de quy tac dong nhat tren Windows, macOS va Linux.
    void purge_expired_logs() const;

private:
    std::string log_directory_;
    mutable std::mutex mutex_;
};
