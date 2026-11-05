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

private:
    std::string log_directory_;
};
