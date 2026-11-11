#include "ztas/audit/audit_logger.hpp"
#include "ztas/authorization/access_service.hpp"
#include "ztas/identity/auth_service.hpp"
#include "ztas/identity/mfa_service.hpp"
#include "ztas/device/device_management_service.hpp"
#include "ztas/device/device_discovery_service.hpp"
#include "ztas/device/device_security_settings_service.hpp"
#include "ztas/device/enrollment_code_service.hpp"
#include "ztas/device/device_registry.hpp"
#include "ztas/data/secure_data_store.hpp"
#include "ztas/policy/policy_client.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <array>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

const ProtectedResource kPublicDocument{
    "public_document", "public", 1,
    "Noi dung tai lieu cong khai"
};

const ProtectedResource kInternalDocument{
    "internal_document", "internal", 2,
    "Noi dung tai lieu noi bo"
};

const ProtectedResource kConfidentialDocument{
    "confidential_document", "confidential", 3,
    "Noi dung tai lieu mat cap noi bo"
};

const ProtectedResource kSecretDocument{
    "secret_document", "secret", 4,
    "Noi dung tai lieu mat"
};

const ProtectedResource kRestrictedDocument{
    "restricted_document", "restricted", 5,
    "Noi dung tai lieu han che dac biet"
};

const std::array<std::string_view, 5> kDocumentZones{
    "public", "internal", "confidential", "secret", "restricted"
};

const ProtectedResource* resource_for_zone(const std::string& zone_id) {
    if (zone_id == "public") return &kPublicDocument;
    if (zone_id == "internal") return &kInternalDocument;
    if (zone_id == "confidential") return &kConfidentialDocument;
    if (zone_id == "secret") return &kSecretDocument;
    if (zone_id == "restricted") return &kRestrictedDocument;
    return nullptr;
}

bool safe_document_name(const std::string& value) {
    if (value.empty() || value.size() > 180) return false;
    const fs::path path(value);
    const std::string filename = path.filename().string();
    return path.filename() == path && value != "." && value != ".." &&
        !filename.empty() && filename.front() != '.';
}

std::string document_content_type(const fs::path& path) {
    const std::string extension = path.extension().string();
    if (extension == ".pdf") return "application/pdf";
    if (extension == ".txt" || extension == ".md" || extension == ".csv") {
        return "text/plain; charset=utf-8";
    }
    if (extension == ".json") return "application/json; charset=utf-8";
    if (extension == ".png") return "image/png";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    return "application/octet-stream";
}

std::size_t stored_file_count(const fs::path& directory) {
    std::error_code error;
    std::size_t count = 0;
    for (const auto& entry : fs::directory_iterator(directory, error)) {
        if (error) return 0;
        if (entry.is_regular_file(error) && !error &&
            entry.path().filename().string().front() != '.') {
            ++count;
        }
    }
    return count;
}

bool write_stored_file(
    const fs::path& target,
    const std::string& content
) {
    const fs::path temporary = target.string() + ".uploading";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file) return false;
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!file) return false;
    }

    std::error_code error;
    fs::rename(temporary, target, error);
    if (error) {
        fs::remove(target, error);
        error.clear();
        fs::rename(temporary, target, error);
    }
    if (error) {
        fs::remove(temporary, error);
        return false;
    }
    return true;
}

std::string env_or_default(
    const char* name,
    const std::string& fallback
) {
    const char* value = std::getenv(name);
    return value != nullptr ? value : fallback;
}

bool env_flag(const char* name, bool fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return fallback;
    }

    std::string normalized(value);
    std::transform(
        normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        }
    );

    return normalized == "1" ||
        normalized == "true" ||
        normalized == "yes";
}

bool valid_mac_address(const std::string& value) {
    if (value.size() != 17) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index % 3 == 2) {
            if (value[index] != ':' && value[index] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(value[index]))) {
            return false;
        }
    }
    return true;
}

bool valid_ip_address(const std::string& value) {
    in_addr ipv4{};
    in6_addr ipv6{};
    return inet_pton(AF_INET, value.c_str(), &ipv4) == 1 ||
        inet_pton(AF_INET6, value.c_str(), &ipv6) == 1;
}

std::optional<std::string> read_text_file(
    const std::string& path
) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }

    std::stringstream content;
    content << file.rdbuf();
    return content.str();
}

std::optional<std::string> read_binary_file(
    const std::string& path
) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    std::stringstream content;
    content << file.rdbuf();
    return content.str();
}

std::optional<json> read_json_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }

    try {
        return json::parse(file);
    } catch (const json::parse_error&) {
        return std::nullopt;
    }
}

json device_inventory(
    const json& policy_data,
    const json& audit_events,
    const json& users_data
) {
    json devices = json::array();
    std::unordered_map<std::string, std::size_t> indexes;
    if (policy_data.contains("devices")) {
        for (auto iterator = policy_data.at("devices").begin();
             iterator != policy_data.at("devices").end();
             ++iterator) {
            const std::string id = iterator.key();
            const json& source = iterator.value();
            const bool registered = source.value("registered", false);

            indexes[id] = devices.size();
            devices.push_back({
                {"id", id},
                {"registered", registered},
                {"trust_level", source.value("trust_level", 0)},
                {"location_id", source.value("location_id", "unknown")},
                {"device_name", source.value("device_name", id)},
                {"device_type", source.value("device_type", "unknown")},
                {"enrollment_profile", source.value("enrollment_profile", "manual")},
                {"lifecycle_status", source.value(
                    "lifecycle_status", registered ? "ACTIVE" : "REVOKED"
                )},
                {"status", registered ? "IDENTIFIED" : "UNIDENTIFIED"},
                {"assigned_accounts", json::array()},
                {"approved", false},
                {"last_event", nullptr},
                {"last_seen", 0}
            });
        }
    }

    // Gan tai khoan vao thiet bi de Dashboard the hien ro danh tinh + thiet bi.
    // Admin voi "*" duoc hien tren moi thiet bi nhu quyen quan tri toan cuc.
    if (users_data.contains("users") && users_data.at("users").is_array()) {
        for (const auto& user : users_data.at("users")) {
            const std::string username = user.value("username", "");
            const std::string role = user.value("role", "");
            if (username.empty() || !user.contains("allowed_device_ids") ||
                !user.at("allowed_device_ids").is_array()) {
                continue;
            }

            for (const auto& allowed_id : user.at("allowed_device_ids")) {
                if (!allowed_id.is_string()) {
                    continue;
                }

                const std::string device_id = allowed_id.get<std::string>();
                const json account = {
                    {"username", username},
                    {"role", role},
                    {"scope", device_id == "*" ? "all" : "device"}
                };

                if (device_id == "*") {
                    for (const auto& [id, index] : indexes) {
                        devices.at(index)["assigned_accounts"].push_back(account);
                    }
                } else if (indexes.find(device_id) != indexes.end()) {
                    devices.at(indexes.at(device_id))["assigned_accounts"]
                        .push_back(account);
                    devices.at(indexes.at(device_id))["approved"] = true;
                }
            }
        }
    }

    // Dashboard chi hien thiet bi da duoc cap phat va co gan tai khoan cu the.
    // May la chi co trong audit/pending_devices.json, khong nam trong day.
    json approved_devices = json::array();
    indexes.clear();
    for (const auto& device : devices) {
        if (!device.value("registered", false) ||
            !device.value("approved", false)) {
            continue;
        }

        json visible_device = device;
        visible_device.erase("approved");
        indexes[visible_device.value("id", "")] = approved_devices.size();
        approved_devices.push_back(visible_device);
    }
    devices = std::move(approved_devices);

    for (const auto& event : audit_events) {
        const std::string id = event.value("device_id", "");
        if (id.empty()) {
            continue;
        }

        if (indexes.find(id) == indexes.end()) {
            // Thiet bi la/thu hoi/xoa chi duoc ghi trong audit, khong hien dashboard.
            continue;
        }

        json& device = devices.at(indexes.at(id));
        const std::string event_type = event.value("event_type", "");

        if (event_type == "DEVICE_PROVISION_SKIPPED" ||
            event_type == "DEVICE_REVOKED") {
            device["status"] = "UNIDENTIFIED";
        } else if (event_type == "DEVICE_ENROLLED" ||
                   event_type == "DEVICE_REENROLLED") {
            device["status"] = "IDENTIFIED";
        } else if (event_type == "AUTHZ_DECISION") {
            if (!event.value("device_key_verified", false)) {
                device["status"] = "UNIDENTIFIED";
            } else if (event.value("effect", "") == "STEP_UP") {
                device["status"] = "STEP_UP";
            } else {
                device["status"] = "IDENTIFIED";
            }
        }

        device["last_event"] = event;
        device["last_seen"] = event.value("timestamp_epoch", 0LL);
    }

    int identified = 0;
    int unidentified = 0;
    int step_up = 0;

    for (const auto& device : devices) {
        const std::string status = device.value("status", "UNIDENTIFIED");
        identified += status == "IDENTIFIED";
        unidentified += status == "UNIDENTIFIED";
        step_up += status == "STEP_UP";
    }

    return {
        {"devices", devices},
        {"summary", {
            {"total", devices.size()},
            {"identified", identified},
            {"unidentified", unidentified},
            {"step_up", step_up}
        }}
    };
}

void send_json(
    httplib::Response& response,
    int status,
    const json& body
) {
    response.status = status;
    response.set_content(
        body.dump(),
        "application/json; charset=utf-8"
    );
}

void send_text_file(
    httplib::Response& response,
    const std::string& path,
    const char* content_type
) {
    const auto content = read_text_file(path);
    if (!content.has_value()) {
        send_json(response, 404, {
            {"error", "STATIC_FILE_NOT_FOUND"}
        });
        return;
    }

    response.set_header("Cache-Control", "no-store");
    response.set_content(*content, content_type);
}

std::optional<std::string> read_bearer_token(
    const httplib::Request& request
) {
    if (request.has_header("Authorization")) {
        const std::string header =
            request.get_header_value("Authorization");

        constexpr std::string_view prefix = "Bearer ";

        if (header.rfind(prefix, 0) == 0 &&
            header.size() > prefix.size()) {
            return header.substr(prefix.size());
        }
    }

    if (!request.has_header("Cookie")) {
        return std::nullopt;
    }

    std::stringstream cookies(request.get_header_value("Cookie"));
    std::string cookie;

    while (std::getline(cookies, cookie, ';')) {
        const auto equal = cookie.find('=');
        if (equal == std::string::npos) {
            continue;
        }

        std::string name = cookie.substr(0, equal);
        std::string value = cookie.substr(equal + 1);
        name.erase(0, name.find_first_not_of(" \t"));
        value.erase(0, value.find_first_not_of(" \t"));

        if ((name == "ZTAS_SESSION_TOKEN" ||
             name == "ZTAS_ADMIN_TOKEN") && !value.empty()) {
            return value;
        }
    }

    return std::nullopt;
}

std::optional<AccessSubject> authenticate_request(
    const httplib::Request& request,
    const AuthService& auth_service,
    httplib::Response& response
) {
    const auto token = read_bearer_token(request);

    const auto subject = token.has_value()
        ? auth_service.verify_token(*token)
        : std::nullopt;

    if (!subject.has_value()) {
        send_json(response, 401, {
            {"error", "UNAUTHENTICATED"},
            {"message", "Can dang nhap bang access token hop le"}
        });
    }

    return subject;
}

bool has_admin_session(
    const httplib::Request& request,
    const AuthService& auth_service
) {
    const auto token = read_bearer_token(request);
    const auto subject = token.has_value()
        ? auth_service.verify_token(*token)
        : std::nullopt;

    return subject.has_value() && subject->role == "admin";
}

bool has_authenticated_session(
    const httplib::Request& request,
    const AuthService& auth_service
) {
    const auto token = read_bearer_token(request);
    return token.has_value() && auth_service.verify_token(*token).has_value();
}

std::optional<AccessSubject> authenticate_admin_request(
    const httplib::Request& request,
    const AuthService& auth_service,
    httplib::Response& response
) {
    const auto subject = authenticate_request(request, auth_service, response);
    if (!subject.has_value()) {
        return std::nullopt;
    }

    if (subject->role != "admin") {
        send_json(response, 403, {
            {"error", "ADMIN_ROLE_REQUIRED"},
            {"message", "Chi role admin duoc phep quan ly thiet bi"}
        });
        return std::nullopt;
    }

    return subject;
}

json decision_json(const AccessDecision& decision) {
    return {
        {"effect", decision.effect},
        {"rule_id", decision.rule_id},
        {"reason_code", decision.reason_code},
        {"severity", decision.severity},
        {"policy_version", decision.policy_version},
        {"current_auth_level", decision.current_auth_level},
        {"required_auth_level", decision.required_auth_level},
        {"resource_id", decision.resource_id}
    };
}

void handle_document_request(
    const httplib::Request& request,
    httplib::Response& response,
    const AuthService& auth_service,
    const DeviceRegistry& device_registry,
    MfaService& mfa_service,
    const AuditLogger& audit_logger,
    const AccessService& access_service,
    const DeviceDiscoveryService& discovery_service,
    const SecureDataStore& data_store,
    const ProtectedResource& resource,
    const std::optional<fs::path>& stored_file = std::nullopt
) {
    const auto subject =
        authenticate_request(request, auth_service, response);

    if (!subject.has_value()) {
        return;
    }

    if (!request.has_header("X-Device-ID") ||
        !request.has_header("X-Location-ID")) {
        send_json(response, 400, {
            {"error", "MISSING_ACCESS_CONTEXT"},
            {"message", "X-Device-ID va X-Location-ID la bat buoc"}
        });
        return;
    }

    const std::string device_id =
        request.get_header_value("X-Device-ID");

    const std::string device_key =
        request.has_header("X-Device-Key")
            ? request.get_header_value("X-Device-Key")
            : "";

    const std::string source_ip = request.remote_addr.empty()
        ? "unknown"
        : request.remote_addr;

    const bool managed_reader_session =
        !subject->reader_device_id.empty() &&
        subject->reader_device_id == device_id &&
        subject->reader_location_id == request.get_header_value("X-Location-ID");
    const bool source_ip_matches_device =
        device_registry.verify_source_ip(device_id, source_ip);
    const bool source_ip_verified = source_ip_matches_device ||
        managed_reader_session;
    const bool device_key_verified = device_registry.verify(device_id, device_key) ||
        managed_reader_session;

    const AccessRequest access_request{
        *subject,
        device_id,
        request.get_header_value("X-Location-ID"),
        device_key_verified,
        source_ip,
        source_ip_verified,
        resource,
        "read"
    };

    const AccessDecision decision =
        access_service.authorize(access_request);

    if (decision.reason_code == "DEVICE_NOT_REGISTERED") {
        const DiscoveryResult discovery = discovery_service.record_attempt(
            device_id,
            request.get_header_value("X-Location-ID"),
            source_ip,
            request.has_header("User-Agent")
                ? request.get_header_value("User-Agent")
                : "unknown"
        );

        if (discovery.success && discovery.first_seen) {
            audit_logger.write({
                {"event_type", "DEVICE_DISCOVERED"},
                {"device_id", device_id},
                {"location_id", request.get_header_value("X-Location-ID")},
                {"username", subject->username},
                {"reason_code", "PENDING_ADMIN_APPROVAL"},
                {"severity", "medium"}
            });
        }
    }

    if (!decision.policy_available) {
        send_json(response, 502, {
            {"error", decision.reason_code},
            {"rule_id", decision.rule_id},
            {"message", "Policy Engine khong phan hoi"}
        });
        return;
    }

    json body = decision_json(decision);

    if (decision.effect == "STEP_UP") {
        const MfaChallenge challenge = mfa_service.issue_challenge(
            *subject,
            decision.required_auth_level
        );

        if (challenge.challenge_id.empty()) {
            audit_logger.write({
                {"event_type", "MFA_CHALLENGE_ERROR"},
                {"username", subject->username},
                {"reason_code", "OTP_GENERATION_FAILED"}
            });
            send_json(response, 500, {
                {"error", "OTP_GENERATION_FAILED"}
            });
            return;
        }

        audit_logger.write({
            {"event_type", "MFA_CHALLENGE_ISSUED"},
            {"username", subject->username},
            {"challenge_id", challenge.challenge_id},
            {"required_auth_level", challenge.required_auth_level},
            {"expires_at", challenge.expires_at}
        });

        body["challenge_id"] = challenge.challenge_id;
        body["expires_at"] = challenge.expires_at;
        body["challenge_type"] = "OTP";

        if (challenge.demo_code.has_value()) {
            body["demo_code"] = *challenge.demo_code;
        }

        send_json(response, 403, body);
        return;
    }

    if (decision.is_permitted()) {
        if (stored_file.has_value()) {
            std::error_code error;
            const auto size = fs::file_size(*stored_file, error);
            if (error || size > 25 * 1024 * 1024) {
                audit_logger.write({
                    {"event_type", "DATA_STORE_ERROR"},
                    {"username", subject->username},
                    {"device_id", device_id},
                    {"resource_id", resource.id},
                    {"reason_code", error ? "STORED_FILE_NOT_FOUND" : "STORED_FILE_TOO_LARGE"},
                    {"severity", "high"}
                });
                send_json(response, error ? 404 : 413, {
                    {"error", error ? "STORED_FILE_NOT_FOUND" : "STORED_FILE_TOO_LARGE"}
                });
                return;
            }

            std::ifstream file(*stored_file, std::ios::binary);
            if (!file) {
                send_json(response, 404, {{"error", "STORED_FILE_NOT_FOUND"}});
                return;
            }
            std::string content(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
            audit_logger.write({
                {"event_type", "STORED_DOCUMENT_READ"},
                {"username", subject->username},
                {"device_id", device_id},
                {"resource_id", resource.id},
                {"stored_file", stored_file->filename().string()},
                {"severity", "info"}
            });
            response.set_header(
                "Content-Disposition",
                "attachment; filename=\"" + stored_file->filename().string() + "\""
            );
            response.set_content(std::move(content), document_content_type(*stored_file));
            return;
        }

        const auto document = data_store.find_document(resource.id);
        if (!document.has_value()) {
            audit_logger.write({
                {"event_type", "DATA_STORE_ERROR"},
                {"username", subject->username},
                {"device_id", device_id},
                {"resource_id", resource.id},
                {"reason_code", "DOCUMENT_NOT_FOUND_IN_DATABASE"},
                {"severity", "critical"}
            });
            send_json(response, 500, {
                {"error", "DOCUMENT_NOT_FOUND_IN_DATABASE"}
            });
            return;
        }

        // Noi dung chi duoc doc tu CSDL sau khi OPA da tra PERMIT.
        body["content"] = document->content;
        body["title"] = document->title;
        body["data_zone"] = document->zone_id;
        send_json(response, 200, body);
        return;
    }

    // DENY va STEP_UP khong bao gio duoc nhan noi dung tai lieu.
    send_json(response, 403, body);
}

} // namespace

int main() {
    const std::string opa_host =
        env_or_default("OPA_HOST", "127.0.0.1");

    const std::string users_file =
        env_or_default("USERS_FILE", "data/users.json");

    const std::string audit_log_directory =
        env_or_default("AUDIT_LOG_DIRECTORY", "data/logs");

    const std::string device_credentials_file =
        env_or_default(
            "DEVICE_CREDENTIALS_FILE",
            "data/device_credentials.json"
        );

    const std::string dashboard_file =
        env_or_default("DASHBOARD_FILE", "web/dashboard.html");

    const std::string logs_file =
        env_or_default("LOGS_FILE", "web/logs.html");

    const std::string accounts_file =
        env_or_default("ACCOUNTS_FILE", "web/accounts.html");

    const std::string documents_file =
        env_or_default("DOCUMENTS_FILE", "web/documents.html");

    const std::string setup_file =
        env_or_default("SETUP_FILE", "web/setup.html");

    const std::string admin_login_file =
        env_or_default("ADMIN_LOGIN_FILE", "web/admin-login.html");

    const std::string devices_policy_file =
        env_or_default("DEVICES_POLICY_FILE", "policies/devices.json");

    const std::string locations_policy_file =
        env_or_default("LOCATIONS_POLICY_FILE", "policies/locations.json");

    const std::string device_environment_directory =
        env_or_default("DEVICE_ENVIRONMENT_DIRECTORY", "runtime/devices");

    const std::string pending_devices_file =
        env_or_default("PENDING_DEVICES_FILE", "data/pending_devices.json");

    const std::string device_security_settings_file =
        env_or_default(
            "DEVICE_SECURITY_SETTINGS_FILE",
            "data/device_security_settings.json"
        );

    const std::string enrollment_codes_file =
        env_or_default("ENROLLMENT_CODES_FILE", "data/enrollment_codes.json");

    const std::string data_store_file =
        env_or_default("DATA_STORE_FILE", "data/ztas.db");

    const std::string document_storage_directory =
        env_or_default("DOCUMENT_STORAGE_DIRECTORY", "data/documents");

    const std::string web_assets_directory =
        env_or_default("WEB_ASSETS_DIRECTORY", "web/assets");

    const std::string web_root_directory =
        env_or_default("WEB_ROOT_DIRECTORY", "web");

    const std::string token_secret =
        env_or_default("APP_TOKEN_SECRET", "");

    const bool demo_mfa_enabled =
        env_flag("ZTAS_DEMO_MFA", false);

    if (token_secret.size() < 32) {
        std::cerr
            << "APP_TOKEN_SECRET phai co it nhat 32 ky tu\n";
        return 1;
    }

    std::error_code storage_error;
    for (const auto zone : kDocumentZones) {
        fs::create_directories(
            fs::path(document_storage_directory) / std::string(zone),
            storage_error
        );
        if (storage_error) {
            std::cerr << "Khong the tao thu muc luu tai lieu: "
                      << storage_error.message() << '\n';
            return 1;
        }
    }

    const AuthService auth_service(
        users_file,
        token_secret
    );

    const PolicyClient policy_client(opa_host);
    const AuditLogger audit_logger(audit_log_directory);
    const SecureDataStore data_store(data_store_file);
    const DeviceRegistry device_registry(
        device_credentials_file,
        devices_policy_file
    );
    const DeviceDiscoveryService discovery_service(pending_devices_file);
    DeviceSecuritySettingsService device_security_settings(
        device_security_settings_file
    );
    const EnrollmentCodeService enrollment_code_service(enrollment_codes_file);
    const DeviceManagementService device_management_service(
        devices_policy_file,
        locations_policy_file,
        device_credentials_file,
        device_environment_directory,
        users_file
    );
    MfaService mfa_service(token_secret, demo_mfa_enabled);
    const AccessService access_service(
        policy_client,
        audit_logger
    );

    if (!data_store.is_ready()) {
        std::cerr << "Khong the khoi tao CSDL PoC: "
                  << data_store.error_message() << std::endl;
        return 1;
    }

    httplib::Server server;
    // Gioi han tai lieu 25 MiB va phan du cho multipart/form-data.
    server.set_payload_max_length(26 * 1024 * 1024);

    server.Get("/health", [&opa_host, demo_mfa_enabled, &data_store](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_json(response, 200, {
            {"service", "ztas"},
            {"status", "UP"},
            {"opa_host", opa_host},
            {"demo_mfa_enabled", demo_mfa_enabled},
            {"data_store", data_store.is_ready() ? "UP" : "DOWN"}
        });
    });

    server.Get("/", [](const httplib::Request&, httplib::Response& response) {
        response.set_redirect("/dashboard");
    });

    const auto serve_login_page = [
        &auth_service,
        &admin_login_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto token = read_bearer_token(request);
        const auto subject = token.has_value()
            ? auth_service.verify_token(*token)
            : std::nullopt;

        if (subject.has_value()) {
            const std::string next = request.has_param("next")
                ? request.get_param_value("next") : "";
            const bool allowed_next = next == "/documents" ||
                (subject->role == "admin" &&
                    (next == "/dashboard" || next == "/logs" ||
                     next == "/accounts"));
            response.set_redirect(allowed_next ? next :
                (subject->role == "admin" ? "/dashboard" : "/documents"));
            return;
        }

        send_text_file(
            response, admin_login_file, "text/html; charset=utf-8"
        );
    };

    server.Get("/login", serve_login_page);
    server.Get("/admin/login", serve_login_page);

    server.Get("/dashboard", [
        &auth_service,
        &dashboard_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        if (!has_admin_session(request, auth_service)) {
            response.set_redirect("/login?next=/dashboard");
            return;
        }
        send_text_file(response, dashboard_file, "text/html; charset=utf-8");
    });

    server.Get("/logs", [
        &auth_service,
        &logs_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        if (!has_admin_session(request, auth_service)) {
            response.set_redirect("/login?next=/logs");
            return;
        }
        send_text_file(response, logs_file, "text/html; charset=utf-8");
    });

    server.Get("/accounts", [
        &auth_service,
        &accounts_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        if (!has_admin_session(request, auth_service)) {
            response.set_redirect("/login?next=/accounts");
            return;
        }
        send_text_file(response, accounts_file, "text/html; charset=utf-8");
    });

    // Menu Tai lieu dung chung phien dang nhap cua he thong, khong co form
    // dang nhap thu hai tren giao dien.
    server.Get("/documents", [&auth_service, &documents_file](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        if (!has_authenticated_session(request, auth_service)) {
            response.set_redirect("/login?next=/documents");
            return;
        }
        send_text_file(response, documents_file, "text/html; charset=utf-8");
    });

    server.Get("/setup", [&setup_file](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(response, setup_file, "text/html; charset=utf-8");
    });

    server.Get("/manifest.webmanifest", [&web_root_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_root_directory + "/manifest.webmanifest",
            "application/manifest+json; charset=utf-8"
        );
    });

    server.Get("/service-worker.js", [&web_root_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_root_directory + "/service-worker.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/app-icon.svg", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/app-icon.svg",
            "image/svg+xml"
        );
    });

    server.Get("/assets/ptit-logo.png", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        const auto content = read_binary_file(
            web_assets_directory + "/ptit-logo.png"
        );
        if (!content.has_value()) {
            send_json(response, 404, {{"error", "STATIC_FILE_NOT_FOUND"}});
            return;
        }
        response.set_content(*content, "image/png");
    });

    server.Get("/assets/ptit-logo-white.png", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        const auto content = read_binary_file(
            web_assets_directory + "/ptit-logo-white.png"
        );
        if (!content.has_value()) {
            send_json(response, 404, {{"error", "STATIC_FILE_NOT_FOUND"}});
            return;
        }
        response.set_content(*content, "image/png");
    });

    server.Get("/assets/common.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/common.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/dashboard.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/dashboard.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/logs.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/logs.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/dashboard.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/dashboard.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/logs.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/logs.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/accounts.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/accounts.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/documents.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/documents.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/common.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/common.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/accounts.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/accounts.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/documents.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/documents.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/setup.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/setup.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/admin-login.css", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/admin-login.css",
            "text/css; charset=utf-8"
        );
    });

    server.Get("/assets/setup.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/setup.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/assets/admin-login.js", [&web_assets_directory](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(
            response,
            web_assets_directory + "/admin-login.js",
            "application/javascript; charset=utf-8"
        );
    });

    server.Get("/api/audit", [&auth_service, &audit_logger](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }
        std::size_t limit = 200;

        if (request.has_param("limit")) {
            try {
                limit = std::clamp<std::size_t>(
                    std::stoul(request.get_param_value("limit")),
                    1,
                    500
                );
            } catch (const std::exception&) {
                send_json(response, 400, {
                    {"error", "INVALID_AUDIT_LIMIT"}
                });
                return;
            }
        }

        std::string selected_date;
        if (request.has_param("date")) {
            selected_date = request.get_param_value("date");
            const bool date_is_valid = selected_date.size() == 10 &&
                selected_date[4] == '-' && selected_date[7] == '-' &&
                std::all_of(
                    selected_date.begin(), selected_date.end(),
                    [](unsigned char character) {
                        return character == '-' || std::isdigit(character);
                    }
                );

            if (!date_is_valid) {
                send_json(response, 400, {
                    {"error", "INVALID_AUDIT_DATE"}
                });
                return;
            }
        }

        const json events = selected_date.empty()
            ? audit_logger.read_recent(limit)
            : audit_logger.read_day(selected_date, limit);
        int permits = 0;
        int denies = 0;
        int step_ups = 0;
        int errors = 0;

        for (const auto& event : events) {
            const std::string effect = event.value("effect", "");
            const std::string event_type = event.value("event_type", "");

            permits += effect == "PERMIT" ||
                event_type == "LOGIN_PERMIT" ||
                event_type == "STEP_UP_PERMIT";
            denies += effect == "DENY" ||
                event_type == "LOGIN_DENY" ||
                event_type == "STEP_UP_DENY";
            step_ups += effect == "STEP_UP";
            errors += event_type.find("ERROR") != std::string::npos;
        }

        send_json(response, 200, {
            {"events", events},
            {"selected_date", selected_date},
            {"retention_days", 5},
            {"summary", {
                {"total", events.size()},
                {"permits", permits},
                {"denies", denies},
                {"step_ups", step_ups},
                {"errors", errors}
            }}
        });
    });

    server.Post("/api/audit/save", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            const std::string date = body.value("date", "");
            const AuditSaveResult result = audit_logger.save_day(date);
            if (!result.success) {
                const int status = result.code == "AUDIT_LOG_NOT_FOUND" ? 404 : 400;
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "AUDIT_LOG_SAVED"},
                {"actor", admin->username},
                {"audit_date", date},
                {"reason_code", "USER_SAVED_AUDIT_LOG"},
                {"severity", "info"}
            });
            send_json(response, 201, {{"message", result.message}});
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    server.Get("/api/setup/status", [&auth_service](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_json(response, 200, {
            {"admin_password_setup_required",
             auth_service.admin_password_setup_required()}
        });
    });

    server.Post("/api/setup/admin-password", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        try {
            const json body = json::parse(request.body);
            const std::string password = body.value("password", "");
            const std::string confirmation = body.value("confirmation", "");

            if (password != confirmation) {
                send_json(response, 400, {
                    {"error", "PASSWORD_CONFIRMATION_MISMATCH"},
                    {"message", "Xac nhan mat khau khong khop"}
                });
                return;
            }

            const PasswordSetupResult result =
                auth_service.set_initial_admin_password(password);

            if (!result.success) {
                const int status =
                    result.code == "ADMIN_PASSWORD_ALREADY_CONFIGURED"
                        ? 409
                        : 400;
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "ADMIN_PASSWORD_CONFIGURED"},
                {"username", "admin"},
                {"severity", "info"}
            });

            send_json(response, 201, {
                {"message", result.message}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {
                {"error", "INVALID_JSON"}
            });
        }
    });

    server.Get("/api/devices", [
        &auth_service,
        &devices_policy_file,
        &users_file,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }
        const auto policy_data = read_json_file(devices_policy_file);
        if (!policy_data.has_value()) {
            send_json(response, 500, {
                {"error", "DEVICES_POLICY_FILE_NOT_FOUND"}
            });
            return;
        }

        const json users_data =
            read_json_file(users_file).value_or(json::object());

        send_json(
            response,
            200,
            device_inventory(
                *policy_data,
                audit_logger.read_recent(500),
                users_data
            )
        );
    });

    server.Get("/api/data-zones", [
        &auth_service,
        &data_store,
        &document_storage_directory
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        json zones = json::array();
        for (const auto& zone : data_store.list_zones()) {
            zones.push_back({
                {"id", zone.zone_id},
                {"name", zone.display_name},
                {"sensitivity", zone.sensitivity},
                {"description", zone.description},
                {"sample_document_count", zone.document_count},
                {"document_count", stored_file_count(
                    fs::path(document_storage_directory) / zone.zone_id
                )},
                {"storage_path", (
                    fs::path(document_storage_directory) / zone.zone_id
                ).string()}
            });
        }

        send_json(response, 200, {
            {"database", "SQLite + protected files"},
            {"zones", zones}
        });
    });

    server.Post("/api/data-zones/upload", [
        &auth_service,
        &document_storage_directory,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) return;

        if (!request.is_multipart_form_data() ||
            !request.form.has_field("zone_id") ||
            !request.form.has_file("document") ||
            request.form.get_file_count("document") != 1) {
            send_json(response, 400, {{"error", "INVALID_UPLOAD_FORM"}});
            return;
        }

        const std::string zone_id = request.form.get_field("zone_id");
        const httplib::FormData file = request.form.get_file("document");
        if (resource_for_zone(zone_id) == nullptr ||
            !safe_document_name(file.filename)) {
            send_json(response, 400, {{"error", "INVALID_DOCUMENT_NAME_OR_ZONE"}});
            return;
        }
        if (file.content.empty() || file.content.size() > 25 * 1024 * 1024) {
            send_json(response, 413, {{"error", "INVALID_DOCUMENT_SIZE"}});
            return;
        }

        const fs::path target =
            fs::path(document_storage_directory) / zone_id / file.filename;
        std::error_code error;
        const bool replaces_existing = fs::exists(target, error) && !error;
        if (!write_stored_file(target, file.content)) {
            send_json(response, 500, {{"error", "STORED_DOCUMENT_WRITE_FAILED"}});
            return;
        }

        audit_logger.write({
            {"event_type", "STORED_DOCUMENT_UPLOADED"},
            {"actor", admin->username},
            {"data_zone", zone_id},
            {"stored_file", file.filename},
            {"file_size", file.content.size()},
            {"replaced_existing", replaces_existing},
            {"severity", "info"}
        });
        send_json(response, replaces_existing ? 200 : 201, {
            {"message", replaces_existing
                ? "Da thay the tai lieu trong phan vung"
                : "Da tai tai lieu vao phan vung"},
            {"zone_id", zone_id},
            {"filename", file.filename},
            {"size", file.content.size()}
        });
    });

    server.Get("/api/users", [
        &auth_service,
        &users_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        const auto users_data = read_json_file(users_file);
        if (!users_data.has_value() || !users_data->contains("users")) {
            send_json(response, 500, {{"error", "USERS_FILE_NOT_FOUND"}});
            return;
        }

        json users = json::array();
        for (const auto& user : users_data->at("users")) {
            users.push_back({
                {"username", user.value("username", "")},
                {"role", user.value("role", "")},
                {"allowed_device_ids", user.value(
                    "allowed_device_ids", json::array()
                )},
                {"temporary_session_minutes", user.value(
                    "temporary_session_minutes", 0
                )}
            });
        }
        send_json(response, 200, {{"users", users}});
    });

    // Chi tra thiet bi da duoc dang ky; thiet bi cho duyet khong duoc gan
    // tai khoan va khong the co quyen truy cap.
    server.Get("/api/registered-devices", [
        &auth_service,
        &devices_policy_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        const auto policy_data = read_json_file(devices_policy_file);
        if (!policy_data.has_value() ||
            !policy_data->contains("devices")) {
            send_json(response, 500, {{"error", "DEVICES_POLICY_FILE_NOT_FOUND"}});
            return;
        }

        json devices = json::array();
        for (auto iterator = policy_data->at("devices").begin();
             iterator != policy_data->at("devices").end();
             ++iterator) {
            const json& device = iterator.value();
            if (!device.value("registered", false)) {
                continue;
            }
            devices.push_back({
                {"id", iterator.key()},
                {"trust_level", device.value("trust_level", 0)},
                {"location_id", device.value("location_id", "unknown")}
            });
        }
        send_json(response, 200, {{"devices", devices}});
    });

    // Tai khoan chi duoc tao boi admin. Mat khau khoi tao do AuthService
    // sinh hash va luu noi bo; API khong bao gio tra password dang ro.
    server.Post("/api/users", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            const UserProvisioningResult result = auth_service.create_user(
                body.value("username", ""),
                body.value("role", "")
            );
            if (!result.success) {
                const int status = result.code == "USERNAME_ALREADY_EXISTS"
                    ? 409
                    : 400;
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "USER_CREATED"},
                {"actor", admin->username},
                {"username", result.username},
                {"role", result.role},
                {"reason_code", "INITIAL_PASSWORD_ASSIGNED"},
                {"severity", "info"}
            });

            send_json(response, 201, {
                {"message", result.message},
                {"user", {
                    {"username", result.username},
                    {"role", result.role}
                }}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    server.Delete("/api/users", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        if (!request.has_param("username")) {
            send_json(response, 400, {{"error", "USERNAME_REQUIRED"}});
            return;
        }

        const UserDeletionResult result = auth_service.delete_user(
            request.get_param_value("username"),
            admin->username
        );

        if (!result.success) {
            const int status = result.code == "USER_NOT_FOUND" ? 404 :
                (result.code == "SELF_DELETION_FORBIDDEN" ||
                 result.code == "LAST_ADMIN_PROTECTED" ? 409 : 400);
            send_json(response, status, {
                {"error", result.code},
                {"message", result.message}
            });
            return;
        }

        audit_logger.write({
            {"event_type", "USER_DELETED"},
            {"actor", admin->username},
            {"username", result.username},
            {"reason_code", "USER_PERMANENTLY_DELETED"},
            {"severity", "high"}
        });

        send_json(response, 200, {
            {"message", result.message},
            {"username", result.username}
        });
    });

    server.Post("/api/user-device-assignments", [
        &auth_service,
        &devices_policy_file,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            const std::string username = body.value("username", "");
            const std::string device_id = body.value("device_id", "");
            const auto policy_data = read_json_file(devices_policy_file);
            const bool registered = policy_data.has_value() &&
                policy_data->contains("devices") &&
                policy_data->at("devices").contains(device_id) &&
                policy_data->at("devices").at(device_id).value("registered", false);

            if (!registered) {
                send_json(response, 400, {
                    {"error", "DEVICE_NOT_REGISTERED"},
                    {"message", "Chi co the gan thiet bi da duoc he thong dang ky"}
                });
                return;
            }

            const DeviceAssignmentResult result =
                auth_service.assign_device(username, device_id);
            if (!result.success) {
                const int status = result.code == "USER_NOT_FOUND" ? 404 :
                    (result.code == "DEVICE_ALREADY_ASSIGNED" ||
                     result.code == "GLOBAL_DEVICE_SCOPE_PROTECTED" ? 409 : 400);
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "USER_DEVICE_ASSIGNED"},
                {"actor", admin->username},
                {"username", result.username},
                {"device_id", result.device_id},
                {"reason_code", "ACCOUNT_DEVICE_BOUND"},
                {"severity", "info"}
            });
            send_json(response, 201, {
                {"message", result.message},
                {"username", result.username},
                {"device_id", result.device_id}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    server.Delete("/api/user-device-assignments", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        if (!request.has_param("username") || !request.has_param("device_id")) {
            send_json(response, 400, {{"error", "ASSIGNMENT_CONTEXT_REQUIRED"}});
            return;
        }

        const DeviceAssignmentResult result = auth_service.unassign_device(
            request.get_param_value("username"),
            request.get_param_value("device_id")
        );
        if (!result.success) {
            const int status = result.code == "USER_NOT_FOUND" ? 404 :
                (result.code == "DEVICE_NOT_ASSIGNED" ||
                 result.code == "GLOBAL_DEVICE_SCOPE_PROTECTED" ? 409 : 400);
            send_json(response, status, {
                {"error", result.code},
                {"message", result.message}
            });
            return;
        }

        audit_logger.write({
            {"event_type", "USER_DEVICE_UNASSIGNED"},
            {"actor", admin->username},
            {"username", result.username},
            {"device_id", result.device_id},
            {"reason_code", "ACCOUNT_DEVICE_UNBOUND"},
            {"severity", "medium"}
        });
        send_json(response, 200, {
            {"message", result.message},
            {"username", result.username},
            {"device_id", result.device_id}
        });
    });

    // Admin tao ma mot lan truoc khi cap cho VM/Docker client. Ma khong cap
    // quyen truy cap du lieu; no chi duoc dung de gui mot yeu cau cho duyet.
    server.Post("/api/enrollment-codes", [
        &auth_service,
        &enrollment_code_service,
        &users_file,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            const std::string username = body.value("assigned_username", "");
            const auto users_data = read_json_file(users_file);
            bool user_exists = false;
            if (users_data.has_value() && users_data->contains("users")) {
                for (const auto& user : users_data->at("users")) {
                    if (user.value("username", "") == username) {
                        user_exists = true;
                        break;
                    }
                }
            }
            if (!user_exists) {
                send_json(response, 400, {
                    {"error", "ASSIGNED_USER_NOT_FOUND"},
                    {"message", "Tai khoan duoc gan khong ton tai"}
                });
                return;
            }

            const EnrollmentCodeIssueResult result = enrollment_code_service.issue(
                body.value("profile", ""),
                username,
                body.value("lifetime_seconds", 600)
            );
            if (!result.success) {
                send_json(response, 400, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "ENROLLMENT_CODE_ISSUED"},
                {"actor", admin->username},
                {"username", result.assigned_username},
                {"enrollment_profile", result.profile.id},
                {"trust_level", result.profile.trust_level},
                {"location_id", result.profile.location_id},
                {"reason_code", "ONE_TIME_CODE_ISSUED"},
                {"severity", "info"}
            });

            send_json(response, 201, {
                {"message", result.message},
                {"enrollment_code", result.enrollment_code},
                {"expires_at", result.expires_at},
                {"profile", {
                    {"id", result.profile.id},
                    {"label", result.profile.label},
                    {"trust_level", result.profile.trust_level},
                    {"location_id", result.profile.location_id}
                }},
                {"assigned_username", result.assigned_username}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    // Chi admin xem va bat/tat thu thap MAC. Khi tat (mac dinh), header MAC
    // bi bo qua hoan toan va khong duoc luu.
    server.Get("/api/device-security-settings", [
        &auth_service,
        &device_security_settings
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) return;
        const DeviceSecuritySettings settings = device_security_settings.get();
        send_json(response, 200, {
            {"mac_capture_enabled", settings.mac_capture_enabled}
        });
    });

    server.Put("/api/device-security-settings", [
        &auth_service,
        &device_security_settings,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) return;
        try {
            const json body = json::parse(request.body);
            const bool enabled = body.value("mac_capture_enabled", false);
            if (!device_security_settings.set_mac_capture_enabled(enabled)) {
                send_json(response, 500, {{"error", "DEVICE_SECURITY_SETTINGS_WRITE_FAILED"}});
                return;
            }
            audit_logger.write({
                {"event_type", "MAC_CAPTURE_SETTING_CHANGED"},
                {"actor", admin->username},
                {"mac_capture_enabled", enabled},
                {"severity", "high"}
            });
            send_json(response, 200, {{"mac_capture_enabled", enabled}});
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    // May moi co the dung ma dang ky mot lan hoac token tai khoan de tu khai
    // bao. Ca hai cach deu chi tao PENDING_APPROVAL, khong cap quyen data.
    server.Post("/api/connection-requests", [
        &auth_service,
        &enrollment_code_service,
        &discovery_service,
        &device_security_settings,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        try {
            const json body = json::parse(request.body);
            const std::string device_id = body.value("device_id", "");
            const std::string location_id = body.value("location_id", "unknown");
            if (device_id.empty()) {
                send_json(response, 400, {
                    {"error", "MISSING_DEVICE_ID"},
                    {"message", "Can gui device_id de yeu cau ket noi"}
                });
                return;
            }

            std::string requested_username;
            std::string enrollment_profile = "manual";
            bool enrollment_verified = false;
            int profile_trust = 0;
            std::string profile_location = location_id;
            const std::string enrollment_code = body.value("enrollment_code", "");

            if (!enrollment_code.empty()) {
                const EnrollmentCodeConsumeResult code_result =
                    enrollment_code_service.consume(enrollment_code);
                if (!code_result.success) {
                    send_json(response, 403, {
                        {"error", code_result.code},
                        {"message", code_result.message}
                    });
                    return;
                }
                requested_username = code_result.assigned_username;
                enrollment_profile = code_result.profile.id;
                enrollment_verified = true;
                profile_trust = code_result.profile.trust_level;
                profile_location = code_result.profile.location_id;
            } else {
                const auto subject =
                    authenticate_request(request, auth_service, response);
                if (!subject.has_value()) {
                    return;
                }
                requested_username = subject->username;
            }

            const DeviceSecuritySettings settings = device_security_settings.get();
            const std::string declared_mac = settings.mac_capture_enabled &&
                    request.has_header("X-Device-MAC")
                ? request.get_header_value("X-Device-MAC")
                : "";
            if (!declared_mac.empty() && !valid_mac_address(declared_mac)) {
                send_json(response, 400, {
                    {"error", "INVALID_DEVICE_MAC"},
                    {"message", "X-Device-MAC phai theo dinh dang 00:11:22:33:44:55"}
                });
                return;
            }

            const DiscoveryResult result = discovery_service.record_attempt(
                device_id,
                profile_location,
                request.remote_addr.empty() ? "unknown" : request.remote_addr,
                request.has_header("User-Agent")
                    ? request.get_header_value("User-Agent")
                    : "unknown",
                declared_mac,
                body.value("device_name", ""),
                body.value("device_type", "unknown"),
                enrollment_profile,
                requested_username,
                enrollment_verified
            );
            if (!result.success) {
                send_json(response, 500, {
                    {"error", "DEVICE_DISCOVERY_FAILED"},
                    {"message", "Khong the luu yeu cau ket noi"}
                });
                return;
            }

            if (result.first_seen) {
                audit_logger.write({
                    {"event_type", "DEVICE_CONNECTION_REQUESTED"},
                    {"device_id", device_id},
                    {"location_id", profile_location},
                {"source_ip", request.remote_addr.empty() ? "unknown" : request.remote_addr},
                    {"username", requested_username},
                    {"enrollment_profile", enrollment_profile},
                    {"trust_level", profile_trust},
                    {"enrollment_verified", enrollment_verified},
                    {"reason_code", "PENDING_ADMIN_APPROVAL"},
                    {"severity", "medium"}
                });
            }

            send_json(response, 202, {
                {"status", "PENDING_ADMIN_APPROVAL"},
                {"device_id", device_id},
                {"enrollment_verified", enrollment_verified},
                {"source_ip", request.remote_addr.empty() ? "unknown" : request.remote_addr},
                {"mac_capture_enabled", settings.mac_capture_enabled},
                {"message", "Yeu cau da duoc gui den quan tri vien"}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    // Hang cho nay chi danh cho giao dien quan tri vien.
    server.Get("/api/device-requests", [
        &auth_service,
        &discovery_service
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        json requests = json::array();
        for (const auto& pending : discovery_service.list_pending()) {
            requests.push_back({
                {"device_id", pending.device_id},
                {"location_id", pending.location_id},
                {"source_ip", pending.source_ip},
                {"declared_mac_address", pending.declared_mac_address},
                {"user_agent", pending.user_agent},
                {"device_name", pending.device_name},
                {"device_type", pending.device_type},
                {"enrollment_profile", pending.enrollment_profile},
                {"requested_username", pending.requested_username},
                {"enrollment_verified", pending.enrollment_verified},
                {"first_seen", pending.first_seen},
                {"last_seen", pending.last_seen},
                {"attempt_count", pending.attempt_count}
            });
        }
        send_json(response, 200, {{"requests", requests}});
    });

    server.Post("/api/devices", [
        &auth_service,
        &device_management_service,
        &discovery_service,
        &device_security_settings,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            std::string source_ip = body.value("allowed_ip_address", "");
            std::string declared_mac;
            for (const auto& pending : discovery_service.list_pending()) {
                if (pending.device_id == body.value("device_id", "")) {
                    if (source_ip.empty()) source_ip = pending.source_ip;
                    declared_mac = pending.declared_mac_address;
                    break;
                }
            }
            if (!device_security_settings.get().mac_capture_enabled) {
                declared_mac.clear();
            }
            if (!valid_ip_address(source_ip)) {
                send_json(response, 400, {
                    {"error", "INVALID_ALLOWED_IP"},
                    {"message", "Can nhap IPv4 hoac IPv6 hop le cua thiet bi de cap quyen truy cap"}
                });
                return;
            }
            const DeviceOperationResult result =
                device_management_service.enroll(
                    body.value("device_id", ""),
                    body.value("trust_level", 0),
                    body.value("location_id", ""),
                    body.value("assigned_username", ""),
                    body.value("device_name", ""),
                    body.value("device_type", "unknown"),
                    body.value("enrollment_profile", "manual"),
                    source_ip,
                    declared_mac
                );

            if (!result.success) {
                const int status = result.code == "DEVICE_ALREADY_ACTIVE"
                    ? 409
                    : 400;
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }

            audit_logger.write({
                {"event_type", result.code},
                {"actor", admin->username},
                {"device_id", result.device_id},
                {"trust_level", result.trust_level},
                {"location_id", result.location_id},
                {"allowed_ip_address", source_ip},
                {"mac_captured", !declared_mac.empty()},
                {"reason_code", result.code},
                {"severity", "info"}
            });

            // Chi xoa hang cho khi cap phat hoan tat. Neu co loi, admin van
            // thay yeu cau de sua phan loai va thu lai.
            const bool request_resolved =
                discovery_service.resolve(result.device_id);
            if (request_resolved) {
                audit_logger.write({
                    {"event_type", "DEVICE_CONNECTION_APPROVED"},
                    {"actor", admin->username},
                    {"device_id", result.device_id},
                    {"trust_level", result.trust_level},
                    {"location_id", result.location_id},
                    {"allowed_ip_address", source_ip},
                    {"reason_code", "DEVICE_ENROLLED_BY_ADMIN"},
                    {"severity", "info"}
                });
            }

            send_json(response, 201, {
                {"message", result.message},
                {"device", {
                    {"id", result.device_id},
                    {"trust_level", result.trust_level},
                    {"location_id", result.location_id},
                    {"device_name", result.device_name},
                    {"device_type", result.device_type},
                    {"enrollment_profile", result.enrollment_profile}
                }},
                {"pending_request_resolved", request_resolved},
                // Chi tra ve key tai thoi diem cap phat. Audit va policy khong luu key dang ro.
                {"device_key", result.device_key}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {
                {"error", "INVALID_JSON"}
            });
        }
    });

    server.Delete("/api/devices", [
        &auth_service,
        &device_management_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        if (!request.has_param("id")) {
            send_json(response, 400, {
                {"error", "MISSING_DEVICE_ID"}
            });
            return;
        }

        const DeviceOperationResult result =
            device_management_service.revoke(
                request.get_param_value("id")
            );

        if (!result.success) {
            const int status = result.code == "DEVICE_NOT_FOUND" ? 404 : 400;
            send_json(response, status, {
                {"error", result.code},
                {"message", result.message}
            });
            return;
        }

        audit_logger.write({
            {"event_type", "DEVICE_REVOKED"},
            {"actor", admin->username},
            {"device_id", result.device_id},
            {"trust_level", result.trust_level},
            {"location_id", result.location_id},
            {"reason_code", "DEVICE_REVOKED"},
            {"severity", "high"}
        });

        send_json(response, 200, {
            {"message", result.message},
            {"device_id", result.device_id}
        });
    });

    server.Put("/api/devices/network-identity", [
        &auth_service,
        &device_management_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) return;

        try {
            const json body = json::parse(request.body);
            const std::string device_id = body.value("device_id", "");
            const std::string source_ip = body.value("allowed_ip_address", "");
            if (!valid_ip_address(source_ip)) {
                send_json(response, 400, {
                    {"error", "INVALID_ALLOWED_IP"},
                    {"message", "IP duoc phep phai la IPv4 hoac IPv6 hop le"}
                });
                return;
            }

            const DeviceOperationResult result =
                device_management_service.update_allowed_ip(device_id, source_ip);
            if (!result.success) {
                send_json(response, result.code == "DEVICE_NOT_FOUND" ? 404 : 400, {
                    {"error", result.code}, {"message", result.message}
                });
                return;
            }
            audit_logger.write({
                {"event_type", "DEVICE_IP_UPDATED"},
                {"actor", admin->username},
                {"device_id", result.device_id},
                {"allowed_ip_address", source_ip},
                {"severity", "high"}
            });
            send_json(response, 200, {
                {"message", result.message},
                {"device_id", result.device_id},
                {"allowed_ip_address", source_ip}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    server.Post("/api/devices/block", [
        &auth_service,
        &device_management_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }
        try {
            const json body = json::parse(request.body);
            const DeviceOperationResult result =
                device_management_service.block(body.value("device_id", ""));
            if (!result.success) {
                const int status = result.code == "DEVICE_NOT_FOUND" ? 404 : 400;
                send_json(response, status, {
                    {"error", result.code},
                    {"message", result.message}
                });
                return;
            }
            audit_logger.write({
                {"event_type", "DEVICE_BLOCKED"},
                {"actor", admin->username},
                {"device_id", result.device_id},
                {"trust_level", result.trust_level},
                {"location_id", result.location_id},
                {"reason_code", "DEVICE_BLOCKED_BY_ADMIN"},
                {"severity", "critical"}
            });
            send_json(response, 200, {
                {"message", result.message},
                {"device_id", result.device_id}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    server.Delete("/api/devices/permanent", [
        &auth_service,
        &device_management_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto admin =
            authenticate_admin_request(request, auth_service, response);
        if (!admin.has_value()) {
            return;
        }

        if (!request.has_param("id")) {
            send_json(response, 400, {
                {"error", "MISSING_DEVICE_ID"}
            });
            return;
        }

        const DeviceOperationResult result =
            device_management_service.remove(
                request.get_param_value("id")
            );

        if (!result.success) {
            const int status = result.code == "DEVICE_NOT_FOUND" ? 404 : 400;
            send_json(response, status, {
                {"error", result.code},
                {"message", result.message}
            });
            return;
        }

        // Chi xoa cau hinh thiet bi; audit log phai luon duoc giu lai.
        audit_logger.write({
            {"event_type", "DEVICE_DELETED"},
            {"actor", admin->username},
            {"device_id", result.device_id},
            {"trust_level", result.trust_level},
            {"location_id", result.location_id},
            {"reason_code", "DEVICE_DELETED"},
            {"severity", "high"}
        });

        send_json(response, 200, {
            {"message", result.message},
            {"device_id", result.device_id}
        });
    });

    server.Post("/api/login", [
        &auth_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        try {
            const json body = json::parse(request.body);
            const std::string username =
                body.value("username", "");
            const std::string password =
                body.value("password", "");

            const auto subject =
                auth_service.authenticate(username, password);

            if (!subject.has_value()) {
                audit_logger.write({
                    {"event_type", "LOGIN_DENY"},
                    {"username", username},
                    {"reason_code", "INVALID_CREDENTIALS"}
                });

                send_json(response, 401, {
                    {"error", "INVALID_CREDENTIALS"}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "LOGIN_PERMIT"},
                {"username", subject->username},
                {"role", subject->role},
                {"auth_level", subject->auth_level}
            });

            const std::string access_token =
                auth_service.issue_token(*subject);

            // Mot cookie HttpOnly dung chung cho toan bo giao dien. Policy
            // van phan biet admin va tai khoan thuong o tung endpoint.
            response.set_header(
                "Set-Cookie",
                "ZTAS_SESSION_TOKEN=" + access_token +
                    "; Path=/; Max-Age=900; HttpOnly; SameSite=Strict"
            );

            send_json(response, 200, {
                {"access_token", access_token},
                {"token_type", "Bearer"},
                {"expires_in", 900},
                {"subject", {
                    {"username", subject->username},
                    {"role", subject->role},
                    {"auth_level", subject->auth_level}
                }}
            });
        } catch (const json::parse_error&) {
            send_json(response, 400, {
                {"error", "INVALID_JSON"}
            });
        }
    });

    server.Post("/api/logout", [](
        const httplib::Request&,
        httplib::Response& response
    ) {
        response.set_header(
            "Set-Cookie",
            "ZTAS_SESSION_TOKEN=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        );
        send_json(response, 200, {{"message", "Da dang xuat"}});
    });

    // Giao dien doc tai lieu chi can username/password. Server rang buoc
    // token ngan han voi thiet bi da duoc cap phat duy nhat khop IP ket noi.
    server.Post("/api/reader-login", [
        &auth_service,
        &device_registry,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        try {
            const json body = json::parse(request.body);
            const auto subject = auth_service.authenticate(
                body.value("username", ""),
                body.value("password", "")
            );
            if (!subject.has_value()) {
                send_json(response, 401, {{"error", "INVALID_CREDENTIALS"}});
                return;
            }

            const std::string source_ip = request.remote_addr.empty()
                ? "unknown" : request.remote_addr;
            const auto context = device_registry.resolve_reader_context(
                subject->allowed_device_ids, source_ip
            );
            if (!context.has_value()) {
                audit_logger.write({
                    {"event_type", "READER_LOGIN_DENY"},
                    {"username", subject->username},
                    {"source_ip", source_ip},
                    {"reason_code", "READER_DEVICE_CONTEXT_NOT_FOUND"},
                    {"severity", "high"}
                });
                send_json(response, 403, {
                    {"error", "READER_DEVICE_CONTEXT_NOT_FOUND"},
                    {"message", "Khong nhan dang duoc mot thiet bi da cap phat cho tai khoan nay tren ket noi hien tai"}
                });
                return;
            }

            audit_logger.write({
                {"event_type", "READER_LOGIN_PERMIT"},
                {"username", subject->username},
                {"device_id", context->device_id},
                {"location_id", context->location_id},
                {"source_ip", source_ip},
                {"severity", "info"}
            });
            send_json(response, 200, {
                {"access_token", auth_service.issue_reader_token(
                    *subject, context->device_id, context->location_id
                )},
                {"token_type", "Bearer"},
                {"expires_in", 900},
                {"subject", {{"username", subject->username}, {"role", subject->role}}},
                {"reader_context", {
                    {"device_id", context->device_id},
                    {"location_id", context->location_id}
                }}
            });
        } catch (const json::exception&) {
            send_json(response, 400, {{"error", "INVALID_JSON"}});
        }
    });

    // Dung lai cookie dang nhap quan tri (hoac Bearer token hop le) khi nguoi
    // dung mo menu Tai lieu. Vi vay admin da dang nhap Dashboard khong phai
    // dang nhap lan thu hai de doc tai lieu.
    server.Get("/api/reader-context", [
        &auth_service,
        &device_registry,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto subject = authenticate_request(request, auth_service, response);
        if (!subject.has_value()) return;

        const std::string source_ip = request.remote_addr.empty()
            ? "unknown" : request.remote_addr;
        const auto context = device_registry.resolve_reader_context(
            subject->allowed_device_ids, source_ip
        );
        if (!context.has_value()) {
            send_json(response, 403, {
                {"error", "READER_DEVICE_CONTEXT_NOT_FOUND"},
                {"message", "Khong nhan dang duoc thiet bi da cap phat tren ket noi hien tai"}
            });
            return;
        }

        audit_logger.write({
            {"event_type", "READER_CONTEXT_RESTORED"},
            {"username", subject->username},
            {"device_id", context->device_id},
            {"location_id", context->location_id},
            {"source_ip", source_ip},
            {"severity", "info"}
        });
        send_json(response, 200, {
            {"access_token", auth_service.issue_reader_token(
                *subject, context->device_id, context->location_id
            )},
            {"token_type", "Bearer"},
            {"expires_in", 900},
            {"subject", {{"username", subject->username}, {"role", subject->role}}},
            {"reader_context", {
                {"device_id", context->device_id},
                {"location_id", context->location_id}
            }}
        });
    });

    // Chi liet ke ten tep sau khi policy da cho phep ngu canh doc. Tep van
    // duoc tai qua endpoint bao ve /documents/<zone>/<filename>.
    server.Get(R"(/api/document-files/([^/]+))", [
        &auth_service,
        &device_registry,
        &access_service,
        &document_storage_directory
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto subject = authenticate_request(request, auth_service, response);
        if (!subject.has_value()) return;
        const std::string zone_id = request.matches[1];
        const ProtectedResource* resource = resource_for_zone(zone_id);
        if (resource == nullptr || !request.has_header("X-Device-ID") ||
            !request.has_header("X-Location-ID")) {
            send_json(response, 400, {{"error", "MISSING_ACCESS_CONTEXT"}});
            return;
        }

        const std::string device_id = request.get_header_value("X-Device-ID");
        const std::string source_ip = request.remote_addr.empty()
            ? "unknown" : request.remote_addr;
        const bool managed_reader_session =
            !subject->reader_device_id.empty() &&
            subject->reader_device_id == device_id &&
            subject->reader_location_id == request.get_header_value("X-Location-ID");
        const bool source_ip_matches_device =
            device_registry.verify_source_ip(device_id, source_ip);
        const bool source_ip_verified = source_ip_matches_device ||
            managed_reader_session;
        const std::string device_key = request.has_header("X-Device-Key")
            ? request.get_header_value("X-Device-Key") : "";
        const AccessDecision decision = access_service.authorize({
            *subject, device_id, request.get_header_value("X-Location-ID"),
            device_registry.verify(device_id, device_key) || managed_reader_session,
            source_ip, source_ip_verified, *resource, "list"
        });
        if (!decision.policy_available) {
            send_json(response, 502, {{"error", decision.reason_code}});
            return;
        }
        if (!decision.is_permitted()) {
            send_json(response, 403, decision_json(decision));
            return;
        }

        json files = json::array();
        std::error_code error;
        const fs::path directory = fs::path(document_storage_directory) / zone_id;
        for (const auto& entry : fs::directory_iterator(directory, error)) {
            if (error) break;
            const std::string filename = entry.path().filename().string();
            if (entry.is_regular_file(error) && !error && safe_document_name(filename)) {
                files.push_back({{"name", filename}, {"size", entry.file_size(error)}});
            }
            error.clear();
        }
        send_json(response, 200, {{"files", files}, {"decision", decision_json(decision)}});
    });

    server.Post("/api/step-up", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto subject =
            authenticate_request(request, auth_service, response);

        if (!subject.has_value()) {
            return;
        }

        try {
            const json body = json::parse(request.body);
            const std::string challenge_id =
                body.value("challenge_id", "");

            const std::string code =
                body.value("mfa_code", "");

            const auto next_auth_level =
                mfa_service.verify_challenge(
                    *subject,
                    challenge_id,
                    code
                );

            if (!next_auth_level.has_value() ||
                *next_auth_level <= subject->auth_level) {
                audit_logger.write({
                    {"event_type", "STEP_UP_DENY"},
                    {"username", subject->username},
                    {"challenge_id", challenge_id},
                    {"reason_code", "INVALID_OR_EXPIRED_MFA_CHALLENGE"}
                });

                send_json(response, 401, {
                    {"error", "INVALID_OR_EXPIRED_MFA_CHALLENGE"}
                });
                return;
            }

            AccessSubject elevated_subject = *subject;
            elevated_subject.auth_level = *next_auth_level;

            audit_logger.write({
                {"event_type", "STEP_UP_PERMIT"},
                {"username", subject->username},
                {"previous_auth_level", subject->auth_level},
                {"new_auth_level", elevated_subject.auth_level}
            });

            send_json(response, 200, {
                {"access_token", auth_service.issue_token(elevated_subject)},
                {"token_type", "Bearer"},
                {"expires_in", 900},
                {"auth_level", elevated_subject.auth_level}
            });
        } catch (const json::parse_error&) {
            send_json(response, 400, {
                {"error", "INVALID_JSON"}
            });
        }
    });

    server.Get("/api/me", [&auth_service](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        const auto subject =
            authenticate_request(request, auth_service, response);

        if (subject.has_value()) {
            send_json(response, 200, {
                {"username", subject->username},
                {"role", subject->role},
                {"auth_level", subject->auth_level}
            });
        }
    });

    server.Get("/documents/public", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, discovery_service, data_store, kPublicDocument
        );
    });

    server.Get("/documents/internal", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, discovery_service, data_store, kInternalDocument
        );
    });

    server.Get("/documents/confidential", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, discovery_service, data_store, kConfidentialDocument
        );
    });

    server.Get("/documents/secret", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, discovery_service, data_store, kSecretDocument
        );
    });

    server.Get("/documents/restricted", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, discovery_service, data_store, kRestrictedDocument
        );
    });

    // Tai lieu do admin dat trong data/documents/<zone>/ chi duoc doc sau
    // khi cung luong Authentication + Device/IP + OPA da cho phep.
    server.Get(R"(/documents/([^/]+)/([^/]+))", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service,
        &discovery_service,
        &data_store,
        &document_storage_directory
    ](const httplib::Request& request, httplib::Response& response) {
        const std::string zone_id = request.matches[1].str();
        const std::string filename = request.matches[2].str();
        const ProtectedResource* resource = resource_for_zone(zone_id);
        if (resource == nullptr || !safe_document_name(filename)) {
            send_json(response, 404, {{"error", "STORED_DOCUMENT_NOT_FOUND"}});
            return;
        }

        const fs::path file_path =
            fs::path(document_storage_directory) / zone_id / filename;
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger, access_service, discovery_service, data_store,
            *resource, file_path
        );
    });

    std::cout << "ZTAS is running at http://localhost:8020" << std::endl;

    if (!server.listen("0.0.0.0", 8020)) {
        std::cerr << "Khong the mo cong 8020: "
                  << std::strerror(errno) << std::endl;
        return 1;
    }

    return 0;
}
