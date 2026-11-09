#include "ztas/data/secure_data_store.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <utility>

namespace fs = std::filesystem;

namespace {

constexpr const char* kSchema = R"sql(
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS data_zones (
    zone_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protected_documents (
    resource_id TEXT PRIMARY KEY,
    zone_id TEXT NOT NULL REFERENCES data_zones(zone_id),
    title TEXT NOT NULL,
    content TEXT NOT NULL
);

INSERT OR IGNORE INTO data_zones(zone_id, display_name, sensitivity, description) VALUES
    ('public', 'Vùng công khai', 'public', 'Dữ liệu công khai, mức bảo vệ 1.'),
    ('internal', 'Vùng nội bộ', 'internal', 'Dữ liệu vận hành nội bộ, mức bảo vệ 2.'),
    ('confidential', 'Vùng mật', 'confidential', 'Dữ liệu nghiệp vụ nhạy cảm, mức bảo vệ 3.'),
    ('secret', 'Vùng bí mật', 'secret', 'Dữ liệu bí mật, yêu cầu MFA cấp cao, mức bảo vệ 4.'),
    ('restricted', 'Vùng hạn chế', 'restricted', 'Dữ liệu hạn chế đặc biệt, chỉ admin cấp 5, mức bảo vệ 5.');

INSERT OR IGNORE INTO protected_documents(resource_id, zone_id, title, content) VALUES
    ('public_document', 'public', 'Tài liệu công khai', 'Noi dung tai lieu cong khai tu CSDL PoC.'),
    ('internal_document', 'internal', 'Tài liệu nội bộ', 'Noi dung tai lieu noi bo tu CSDL PoC.'),
    ('confidential_document', 'confidential', 'Tài liệu mật', 'Noi dung tai lieu mat cap noi bo tu CSDL PoC.'),
    ('secret_document', 'secret', 'Tài liệu bí mật', 'Noi dung tai lieu bi mat tu CSDL PoC.'),
    ('restricted_document', 'restricted', 'Tài liệu hạn chế', 'Noi dung tai lieu han che dac biet tu CSDL PoC.');
)sql";

} // namespace

SecureDataStore::SecureDataStore(std::string database_file)
    : database_file_(std::move(database_file)) {
    const fs::path path(database_file_);
    std::error_code error;
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path(), error);
    }

    if (error || sqlite3_open_v2(
            database_file_.c_str(),
            &database_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nullptr
        ) != SQLITE_OK) {
        error_message_ = database_ != nullptr
            ? sqlite3_errmsg(database_)
            : "Khong the mo CSDL SQLite";
        return;
    }

    sqlite3_busy_timeout(database_, 2000);
    initialize_schema();
}

SecureDataStore::~SecureDataStore() {
    if (database_ != nullptr) {
        sqlite3_close(database_);
    }
}

bool SecureDataStore::is_ready() const {
    return database_ != nullptr && error_message_.empty();
}

std::string SecureDataStore::error_message() const {
    return error_message_;
}

bool SecureDataStore::execute(const char* sql) {
    char* error = nullptr;
    const int result = sqlite3_exec(database_, sql, nullptr, nullptr, &error);
    if (result == SQLITE_OK) {
        return true;
    }

    error_message_ = error != nullptr ? error : sqlite3_errmsg(database_);
    sqlite3_free(error);
    return false;
}

bool SecureDataStore::initialize_schema() {
    if (database_ == nullptr) {
        return false;
    }
    return execute(kSchema);
}

std::optional<StoredDocument> SecureDataStore::find_document(
    const std::string& resource_id
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_ready()) {
        return std::nullopt;
    }

    constexpr const char* query = R"sql(
        SELECT resource_id, zone_id, title, content
        FROM protected_documents WHERE resource_id = ?1
    )sql";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, query, -1, &statement, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(statement, 1, resource_id.c_str(), -1, SQLITE_TRANSIENT);
    const int result = sqlite3_step(statement);
    if (result != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return std::nullopt;
    }

    const auto column = [statement](int index) {
        const auto* value = sqlite3_column_text(statement, index);
        return value == nullptr ? std::string{} :
            std::string(reinterpret_cast<const char*>(value));
    };

    StoredDocument document{
        column(0), column(1), column(2), column(3)
    };
    sqlite3_finalize(statement);
    return document;
}

std::vector<DataZone> SecureDataStore::list_zones() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DataZone> zones;
    if (!is_ready()) {
        return zones;
    }

    constexpr const char* query = R"sql(
        SELECT z.zone_id, z.display_name, z.sensitivity, z.description,
               COUNT(d.resource_id)
        FROM data_zones z
        LEFT JOIN protected_documents d ON d.zone_id = z.zone_id
        GROUP BY z.zone_id, z.display_name, z.sensitivity, z.description
        ORDER BY CASE z.zone_id
            WHEN 'public' THEN 1 WHEN 'internal' THEN 2
            WHEN 'confidential' THEN 3 WHEN 'secret' THEN 4 ELSE 5 END
    )sql";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, query, -1, &statement, nullptr) != SQLITE_OK) {
        return zones;
    }

    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto column = [statement](int index) {
            const auto* value = sqlite3_column_text(statement, index);
            return value == nullptr ? std::string{} :
                std::string(reinterpret_cast<const char*>(value));
        };
        zones.push_back({
            column(0), column(1), column(2), column(3),
            sqlite3_column_int(statement, 4)
        });
    }
    sqlite3_finalize(statement);
    return zones;
}
