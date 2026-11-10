#include "ztas/audit/audit_logger.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

namespace {

constexpr int kRetentionDays = 5;

std::tm local_time(std::time_t value) {
    std::tm output{};
#ifdef _WIN32
    localtime_s(&output, &value);
#else
    localtime_r(&value, &output);
#endif
    return output;
}

std::string local_log_date() {
    const std::tm now = local_time(std::time(nullptr));
    std::ostringstream output;
    output << std::put_time(&now, "%Y-%m-%d");
    return output.str();
}

bool is_log_date(const std::string& date) {
    return date.size() == 10 && date[4] == '-' && date[7] == '-' &&
        std::all_of(date.begin(), date.end(), [](unsigned char character) {
            return character == '-' || std::isdigit(character);
        });
}

std::time_t date_at_midnight(const std::string& date) {
    if (!is_log_date(date)) {
        return static_cast<std::time_t>(-1);
    }

    try {
        std::tm value{};
        value.tm_year = std::stoi(date.substr(0, 4)) - 1900;
        value.tm_mon = std::stoi(date.substr(5, 2)) - 1;
        value.tm_mday = std::stoi(date.substr(8, 2));
        value.tm_isdst = -1;
        return std::mktime(&value);
    } catch (const std::exception&) {
        return static_cast<std::time_t>(-1);
    }
}

bool is_expired(const std::string& date) {
    const std::time_t candidate = date_at_midnight(date);
    if (candidate == static_cast<std::time_t>(-1)) {
        return false;
    }

    std::tm today = local_time(std::time(nullptr));
    today.tm_hour = 0;
    today.tm_min = 0;
    today.tm_sec = 0;
    today.tm_isdst = -1;
    const std::time_t today_midnight = std::mktime(&today);
    return std::difftime(today_midnight, candidate) >=
        static_cast<double>(kRetentionDays * 24 * 60 * 60);
}

std::filesystem::path daily_path(const std::string& directory) {
    return std::filesystem::path(directory) / (local_log_date() + ".jsonl");
}

std::filesystem::path saved_directory(const std::string& directory) {
    return std::filesystem::path(directory).parent_path() / "saved-logs";
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
            // Bo qua dong JSON dang ghi do dang hoac khong hop le.
        }
    }

    return nlohmann::json(records);
}

} // namespace

AuditLogger::AuditLogger(std::string log_directory)
    : log_directory_(std::move(log_directory)) {
    purge_expired_logs();
}

void AuditLogger::write(const nlohmann::json& event) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::filesystem::path path = daily_path(log_directory_);
    std::error_code error;

    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), error);
    }
    if (error) {
        return;
    }

    auto record = event;
    record["timestamp_epoch"] = std::chrono::duration_cast<
        std::chrono::seconds
    >(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::ofstream file(path, std::ios::app);
    if (file) {
        file << record.dump() << '\n';
    }

    // Da co mutex, goi phien ban noi bo de tranh khoa lap.
    const std::filesystem::path directory(log_directory_);
    if (!std::filesystem::exists(directory, error)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".jsonl") {
            continue;
        }
        const std::string date = entry.path().stem().string();
        if (is_log_date(date) && is_expired(date)) {
            std::filesystem::remove(entry.path(), error);
            error.clear();
        }
    }
}

nlohmann::json AuditLogger::read_recent(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
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

    std::lock_guard<std::mutex> lock(mutex_);
    const std::filesystem::path active =
        std::filesystem::path(log_directory_) / (date + ".jsonl");
    std::error_code error;
    const std::filesystem::path source = std::filesystem::exists(active, error)
        ? active
        : saved_directory(log_directory_) / (date + ".jsonl");
    return read_jsonl_file(source, limit);
}

AuditSaveResult AuditLogger::save_day(const std::string& date) const {
    if (!is_log_date(date)) {
        return {false, "INVALID_AUDIT_DATE", "Ngay log khong hop le"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const std::filesystem::path source =
        std::filesystem::path(log_directory_) / (date + ".jsonl");
    std::error_code error;
    if (!std::filesystem::exists(source, error)) {
        return {false, "AUDIT_LOG_NOT_FOUND", "Khong tim thay log cua ngay da chon"};
    }

    const std::filesystem::path directory = saved_directory(log_directory_);
    std::filesystem::create_directories(directory, error);
    if (error) {
        return {false, "AUDIT_SAVE_DIRECTORY_ERROR", "Khong tao duoc thu muc luu log rieng"};
    }

    const std::filesystem::path destination = directory / (date + ".jsonl");
    std::filesystem::copy_file(
        source,
        destination,
        std::filesystem::copy_options::overwrite_existing,
        error
    );
    if (error) {
        return {false, "AUDIT_SAVE_ERROR", "Khong the luu rieng log da chon"};
    }

    return {true, "AUDIT_LOG_SAVED", "Da luu rieng log; ban sao nay khong bi xoa sau 5 ngay"};
}

void AuditLogger::purge_expired_logs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::error_code error;
    const std::filesystem::path directory(log_directory_);
    if (!std::filesystem::exists(directory, error)) {
        return;
    }

    const auto remove_expired = [&error](const std::filesystem::path& path) {
        const std::string date = path.stem().string();
        if (is_log_date(date) && is_expired(date)) {
            std::filesystem::remove(path, error);
            error.clear();
        }
    };

    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        if (entry.is_regular_file() && entry.path().extension() == ".jsonl") {
            remove_expired(entry.path());
        }
    }

    // Xoa archive XML cua phien ban cu, vi chung khong phai ban luu rieng do
    // nguoi dung yeu cau va se vo hieu hoa retention neu giu lai.
    const std::filesystem::path legacy_archive = directory.parent_path() / "archive";
    if (!std::filesystem::exists(legacy_archive, error)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(legacy_archive, error)) {
        if (entry.is_regular_file() && entry.path().extension() == ".xml") {
            remove_expired(entry.path());
        }
    }
}
