#include "ztas/audit/audit_logger.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

namespace {

std::string local_log_date() {
    const std::time_t now = std::time(nullptr);
    std::tm local_time{};
#ifdef _WIN32
    localtime_s(&local_time, &now);
#else
    localtime_r(&now, &local_time);
#endif
    std::ostringstream output;
    output << std::put_time(&local_time, "%Y-%m-%d");
    return output.str();
}

std::filesystem::path daily_path(const std::string& directory) {
    return std::filesystem::path(directory) /
        (local_log_date() + ".jsonl");
}

} // namespace

AuditLogger::AuditLogger(std::string log_directory)
    : log_directory_(std::move(log_directory)) {}

void AuditLogger::write( const nlohmann::json& event) const{
    const std::filesystem::path path = daily_path(log_directory_);

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
        path,
        std::ios::app
    );
    if(file){
        file << record.dump() << std::endl;
    }
}

nlohmann::json AuditLogger::read_recent(std::size_t limit) const {
    std::deque<nlohmann::json> records;
    std::vector<std::filesystem::path> files;
    std::error_code error;
    const std::filesystem::path directory(log_directory_);

    if (!std::filesystem::exists(directory, error)) {
        return nlohmann::json(records);
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        if (entry.is_regular_file() && entry.path().extension() == ".jsonl") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    for (const auto& path : files) {
        std::ifstream file(path);
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
                // Bo qua dong JSON chua hoan chinh hoac loi.
            }
        }
    }
    return nlohmann::json(records);
}
