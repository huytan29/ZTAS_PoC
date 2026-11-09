#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

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

    // Xuat JSONL cua cac ngay da qua thanh XML trong data/archive/.
    void archive_previous_days() const;

private:
    std::string log_directory_;
};
