#include "ztas/audit/audit_logger.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
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

bool is_log_date(const std::string& date) {
    return date.size() == 10 && date[4] == '-' && date[7] == '-' &&
        std::all_of(date.begin(), date.end(), [](unsigned char character) {
            return character == '-' || std::isdigit(character);
        });
}

std::string xml_escape(const std::string& value) {
    std::string output;
    output.reserve(value.size());

    for (const char character : value) {
        switch (character) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '\"': output += "&quot;"; break;
        case '\'': output += "&apos;"; break;
        default: output.push_back(character); break;
        }
    }

    return output;
}

std::string json_value_text(const nlohmann::json& value) {
    return value.is_string() ? value.get<std::string>() : value.dump();
}

nlohmann::json read_jsonl_file(
    const std::filesystem::path& path,
    std::size_t limit
) {
    std::deque<nlohmann::json> records;
    std::ifstream file(path);
    std::string line;

    while (std::getline(file, line)) {
        try {
            records.push_back(nlohmann::json::parse(line));
            if (records.size() > limit) {
                records.pop_front();
            }
        } catch (const nlohmann::json::parse_error&) {
            // Bo qua dong JSON chua hoan chinh hoac loi.
        }
    }

    return nlohmann::json(records);
}

} // namespace

AuditLogger::AuditLogger(std::string log_directory)
    : log_directory_(std::move(log_directory)) {
    archive_previous_days();
}

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

    archive_previous_days();
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
        for (const auto& record : read_jsonl_file(path, limit)) {
            records.push_back(record);
            if (records.size() > limit) {
                records.pop_front();
            }
        }
    }
    return nlohmann::json(records);
}

nlohmann::json AuditLogger::read_day(
    const std::string& date,
    std::size_t limit
) const {
    if (!is_log_date(date)) {
        return nlohmann::json::array();
    }

    return read_jsonl_file(
        std::filesystem::path(log_directory_) / (date + ".jsonl"),
        limit
    );
}

void AuditLogger::archive_previous_days() const {
    const std::filesystem::path directory(log_directory_);
    const std::filesystem::path archive_directory =
        directory.parent_path() / "archive";
    const std::string today = local_log_date();
    std::error_code error;

    if (!std::filesystem::exists(directory, error)) {
        return;
    }

    std::filesystem::create_directories(archive_directory, error);
    if (error) {
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".jsonl") {
            continue;
        }

        const std::string date = entry.path().stem().string();
        if (!is_log_date(date) || date >= today) {
            continue;
        }

        const nlohmann::json records = read_jsonl_file(
            entry.path(), std::numeric_limits<std::size_t>::max()
        );
        const std::filesystem::path xml_path = archive_directory / (date + ".xml");
        const std::filesystem::path temporary_path = xml_path.string() + ".tmp";
        std::ofstream xml(temporary_path);

        if (!xml) {
            continue;
        }

        xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        xml << "<audit date=\"" << date << "\">\n";
        for (const auto& record : records) {
            xml << "  <event>\n";
            for (auto iterator = record.begin(); iterator != record.end(); ++iterator) {
                xml << "    <field name=\"" << xml_escape(iterator.key()) << "\">"
                    << xml_escape(json_value_text(iterator.value()))
                    << "</field>\n";
            }
            xml << "  </event>\n";
        }
        xml << "</audit>\n";
        xml.close();

        std::filesystem::rename(temporary_path, xml_path, error);
        if (error) {
            std::filesystem::remove(xml_path, error);
            error.clear();
            std::filesystem::rename(temporary_path, xml_path, error);
        }
    }
}
