#include "ztas/audit/audit_logger.hpp"
#include "ztas/authorization/access_service.hpp"
#include "ztas/identity/auth_service.hpp"
#include "ztas/identity/mfa_service.hpp"
#include "ztas/device/device_management_service.hpp"
#include "ztas/device/device_registry.hpp"
#include "ztas/policy/policy_client.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

using json = nlohmann::json;

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
    const json& audit_events
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
                {"status", registered ? "IDENTIFIED" : "UNIDENTIFIED"},
                {"last_event", nullptr},
                {"last_seen", 0}
            });
        }
    }

    for (const auto& event : audit_events) {
        const std::string id = event.value("device_id", "");
        if (id.empty()) {
            continue;
        }

        if (indexes.find(id) == indexes.end()) {
            indexes[id] = devices.size();
            devices.push_back({
                {"id", id},
                {"registered", false},
                {"trust_level", 0},
                {"location_id", event.value("location_id", "unknown")},
                {"status", "UNIDENTIFIED"},
                {"last_event", nullptr},
                {"last_seen", 0}
            });
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

        if (name == "ZTAS_ADMIN_TOKEN" && !value.empty()) {
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
    const ProtectedResource& resource
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

    const AccessRequest access_request{
        *subject,
        device_id,
        request.get_header_value("X-Location-ID"),
        device_registry.verify(device_id, device_key),
        resource,
        "read"
    };

    const AccessDecision decision =
        access_service.authorize(access_request);

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
        body["content"] = resource.content;
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

    const std::string web_assets_directory =
        env_or_default("WEB_ASSETS_DIRECTORY", "web/assets");

    const std::string token_secret =
        env_or_default("APP_TOKEN_SECRET", "");

    const bool demo_mfa_enabled =
        env_flag("ZTAS_DEMO_MFA", false);

    if (token_secret.size() < 32) {
        std::cerr
            << "APP_TOKEN_SECRET phai co it nhat 32 ky tu\n";
        return 1;
    }

    const AuthService auth_service(
        users_file,
        token_secret
    );

    const PolicyClient policy_client(opa_host);
    const AuditLogger audit_logger(audit_log_directory);
    const DeviceRegistry device_registry(device_credentials_file);
    const DeviceManagementService device_management_service(
        devices_policy_file,
        locations_policy_file,
        device_credentials_file,
        device_environment_directory
    );
    MfaService mfa_service(token_secret, demo_mfa_enabled);
    const AccessService access_service(
        policy_client,
        audit_logger
    );

    httplib::Server server;

    server.Get("/health", [&opa_host, demo_mfa_enabled](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_json(response, 200, {
            {"service", "ztas"},
            {"status", "UP"},
            {"opa_host", opa_host},
            {"demo_mfa_enabled", demo_mfa_enabled}
        });
    });

    server.Get("/", [](const httplib::Request&, httplib::Response& response) {
        response.set_redirect("/dashboard");
    });

    server.Get("/admin/login", [
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

        if (subject.has_value() && subject->role == "admin") {
            response.set_redirect("/dashboard");
            return;
        }

        send_text_file(
            response, admin_login_file, "text/html; charset=utf-8"
        );
    });

    server.Get("/dashboard", [
        &auth_service,
        &dashboard_file
    ](
        const httplib::Request& request,
        httplib::Response& response
    ) {
        if (!has_admin_session(request, auth_service)) {
            response.set_redirect("/admin/login?next=/dashboard");
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
            response.set_redirect("/admin/login?next=/logs");
            return;
        }
        send_text_file(response, logs_file, "text/html; charset=utf-8");
    });

    server.Get("/setup", [&setup_file](
        const httplib::Request&,
        httplib::Response& response
    ) {
        send_text_file(response, setup_file, "text/html; charset=utf-8");
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

        const json events = audit_logger.read_recent(limit);
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
            {"summary", {
                {"total", events.size()},
                {"permits", permits},
                {"denies", denies},
                {"step_ups", step_ups},
                {"errors", errors}
            }}
        });
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

        send_json(
            response,
            200,
            device_inventory(
                *policy_data,
                audit_logger.read_recent(500)
            )
        );
    });

    server.Post("/api/devices", [
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
                device_management_service.enroll(
                    body.value("device_id", ""),
                    body.value("trust_level", 0),
                    body.value("location_id", "")
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
                {"reason_code", result.code},
                {"severity", "info"}
            });

            send_json(response, 201, {
                {"message", result.message},
                {"device", {
                    {"id", result.device_id},
                    {"trust_level", result.trust_level},
                    {"location_id", result.location_id}
                }},
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

            // Cookie HttpOnly cho man hinh quan tri. API van co the nhan
            // Authorization: Bearer de phuc vu client/CLI cua PoC.
            if (subject->role == "admin") {
                response.set_header(
                    "Set-Cookie",
                    "ZTAS_ADMIN_TOKEN=" + access_token +
                        "; Path=/; Max-Age=900; HttpOnly; SameSite=Strict"
                );
            }

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
            "ZTAS_ADMIN_TOKEN=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        );
        send_json(response, 200, {{"message", "Da dang xuat"}});
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
        &access_service
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, kPublicDocument
        );
    });

    server.Get("/documents/internal", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, kInternalDocument
        );
    });

    server.Get("/documents/confidential", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, kConfidentialDocument
        );
    });

    server.Get("/documents/secret", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, kSecretDocument
        );
    });

    server.Get("/documents/restricted", [
        &auth_service,
        &device_registry,
        &mfa_service,
        &audit_logger,
        &access_service
    ](const httplib::Request& request, httplib::Response& response) {
        handle_document_request(
            request, response, auth_service, device_registry, mfa_service,
            audit_logger,
            access_service, kRestrictedDocument
        );
    });

    std::cout << "ZTAS is running at http://127.0.0.1:8020\n";
    return server.listen("0.0.0.0", 8020) ? 0 : 1;
}
