#include "ztas/audit/audit_logger.hpp"
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>

AuditLogger::AuditLogger(std::string file_path)
    : file_path_(std::move(file_path)) {}

void AuditLogger::write( const nlohmann::json& event) const{
    const std::filesystem::path path(file_path_);

    std::error_code error;
    if(!path.parent_path().empty()) {
        std::filesystem::create_directories(
            path.parent_path(),
            error
        );
    }
    if(error){
        return;
    }
    auto record = event;

    const auto now = 
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now()
                .time_since_epoch()
        ).count();
    record["timestamp_epoch"] = now;

    std::ofstream file(
        file_path_,
        std::ios::app
    );
    if(file){
        file << record.dump() << std::endl;
    }
}

nlohmann::json AuditLogger::read_recent(std::size_t limit) const {
    std::ifstream file(file_path_);
    std::deque<nlohmann::json> records;
    std::string line;

    while(std::getline(file, line)) {
        try{
            records.push_back(
                nlohmann::json::parse(line)
            );
            if(records.size() > limit) {
                records.pop_front();
            }
        } catch (const nlohmann::json::parse_error&) {
            //Bo qua dong JSON chua hoan chinh hoac loi
        }
    }
    return nlohmann::json(records);
}