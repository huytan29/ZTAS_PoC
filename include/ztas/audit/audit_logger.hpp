#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

class AuditLogger {
public:
    explicit AuditLogger(std::string file_path);

    void write(const nlohmann::json& event) const;

    nlohmann::json read_recent(
        std::size_t limit
    ) const;

private:
    std::string file_path_;
};