#include "ztas/device/enrollment_code_service.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

const std::array<EnrollmentProfile, 5> kProfiles = {{
    {"guest", "Guest", 1, "external-network"},
    {"unmanaged", "Unmanaged", 2, "external-network"},
    {"managed-vm", "Managed VM", 3, "lab-network"},
    {"trusted", "Trusted", 4, "campus-network"},
    {"secure", "Secure", 5, "secure-zone"}
}};

long long current_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string hex_encode(const unsigned char* input, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);
    for (std::size_t index = 0; index < length; ++index) {
        output.push_back(digits[(input[index] >> 4) & 0x0f]);
        output.push_back(digits[input[index] & 0x0f]);
    }
    return output;
}

std::string create_code() {
    unsigned char bytes[24];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        throw std::runtime_error("Khong the sinh ma dang ky");
    }
    return "enr_" + hex_encode(bytes, sizeof(bytes));
}

std::string hash_code(const std::string& value) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    if (EVP_Digest(
            value.data(), value.size(), digest, &digest_length,
            EVP_sha256(), nullptr
        ) != 1) {
        throw std::runtime_error("Khong the bam ma dang ky");
    }
    return hex_encode(digest, digest_length);
}

json read_codes(const fs::path& path) {
    json store = {{"schema_version", 1}, {"codes", json::object()}};
    if (!fs::exists(path)) {
        return store;
    }
    std::ifstream file(path);
    store = json::parse(file);
    if (!store.contains("codes") || !store["codes"].is_object()) {
        store["codes"] = json::object();
    }
    return store;
}

void write_codes(const fs::path& path, const json& store) {
    fs::create_directories(path.parent_path());
    const fs::path temporary = path.string() + ".tmp";
    {
        std::ofstream file(temporary);
        if (!file) {
            throw std::runtime_error("Khong ghi duoc kho ma dang ky");
        }
        file << store.dump(2) << '\n';
    }
    std::error_code error;
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
    }
    if (error) {
        throw std::runtime_error("Khong cap nhat duoc kho ma dang ky");
    }
}

void discard_expired(json& store, long long now) {
    for (auto iterator = store["codes"].begin();
         iterator != store["codes"].end();) {
        if (iterator.value().value("expires_at", 0LL) <= now) {
            iterator = store["codes"].erase(iterator);
        } else {
            ++iterator;
        }
    }
}

} // namespace

EnrollmentCodeService::EnrollmentCodeService(std::string code_store_file)
    : code_store_file_(std::move(code_store_file)) {}

const EnrollmentProfile* EnrollmentCodeService::find_profile(
    const std::string& profile_id
) {
    for (const auto& profile : kProfiles) {
        if (profile.id == profile_id) {
            return &profile;
        }
    }
    return nullptr;
}

EnrollmentCodeIssueResult EnrollmentCodeService::issue(
    const std::string& profile_id,
    const std::string& assigned_username,
    int lifetime_seconds
) const {
    const EnrollmentProfile* profile = find_profile(profile_id);
    if (profile == nullptr) {
        return {false, "INVALID_ENROLLMENT_PROFILE", "Profile cap phat khong hop le"};
    }
    if (assigned_username.empty()) {
        return {false, "ASSIGNED_USER_REQUIRED", "Can chon tai khoan su dung thiet bi"};
    }
    if (lifetime_seconds < 60 || lifetime_seconds > 3600) {
        return {false, "INVALID_CODE_LIFETIME", "Ma dang ky chi co the co han tu 1 den 60 phut"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    try {
        const fs::path path(code_store_file_);
        json store = read_codes(path);
        const long long now = current_epoch();
        discard_expired(store, now);
        const std::string code = create_code();
        const long long expires_at = now + lifetime_seconds;
        store["codes"][hash_code(code)] = {
            {"profile_id", profile->id},
            {"assigned_username", assigned_username},
            {"expires_at", expires_at},
            {"created_at", now}
        };
        write_codes(path, store);
        return {true, "ENROLLMENT_CODE_ISSUED", "Da cap ma dang ky dung mot lan", code, *profile, assigned_username, expires_at};
    } catch (const std::exception& error) {
        return {false, "ENROLLMENT_CODE_ISSUE_ERROR", error.what()};
    }
}

EnrollmentCodeConsumeResult EnrollmentCodeService::consume(
    const std::string& enrollment_code
) const {
    if (enrollment_code.empty()) {
        return {false, "ENROLLMENT_CODE_REQUIRED", "Can gui ma dang ky"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    try {
        const fs::path path(code_store_file_);
        json store = read_codes(path);
        const long long now = current_epoch();
        discard_expired(store, now);
        const std::string code_hash = hash_code(enrollment_code);
        if (!store["codes"].contains(code_hash)) {
            write_codes(path, store);
            return {false, "ENROLLMENT_CODE_INVALID", "Ma dang ky khong hop le, da dung hoac da het han"};
        }
        const json record = store["codes"][code_hash];
        const auto* profile = find_profile(record.value("profile_id", ""));
        if (profile == nullptr) {
            return {false, "ENROLLMENT_PROFILE_INVALID", "Profile trong ma dang ky khong hop le"};
        }
        const std::string username = record.value("assigned_username", "");
        store["codes"].erase(code_hash);
        write_codes(path, store);
        return {true, "ENROLLMENT_CODE_ACCEPTED", "Ma dang ky hop le", *profile, username};
    } catch (const std::exception& error) {
        return {false, "ENROLLMENT_CODE_CONSUME_ERROR", error.what()};
    }
}
