#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

struct StoredDocument {
    std::string resource_id;
    std::string zone_id;
    std::string title;
    std::string content;
};

struct DataZone {
    std::string zone_id;
    std::string display_name;
    std::string sensitivity;
    std::string description;
    int document_count = 0;
};

// CSDL noi bo cho PoC. Chi ZTAS mo file SQLite; thiet bi khong ket noi
// truc tiep ma phai di qua Authentication + OPA Policy + PEP.
class SecureDataStore {
public:
    explicit SecureDataStore(std::string database_file);
    ~SecureDataStore();

    SecureDataStore(const SecureDataStore&) = delete;
    SecureDataStore& operator=(const SecureDataStore&) = delete;

    bool is_ready() const;
    std::string error_message() const;

    std::optional<StoredDocument> find_document(
        const std::string& resource_id
    ) const;

    std::vector<DataZone> list_zones() const;

private:
    bool initialize_schema();
    bool execute(const char* sql);

    std::string database_file_;
    mutable std::mutex mutex_;
    sqlite3* database_ = nullptr;
    std::string error_message_;
};
