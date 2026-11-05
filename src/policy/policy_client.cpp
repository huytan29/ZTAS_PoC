#include "ztas/policy/policy_client.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <utility>

PolicyClient::PolicyClient(std::string opa_host)
    : opa_host_(std::move(opa_host)) {}

std::optional<AccessDecision> PolicyClient::decide(
    const AccessRequest& request
) const {
    httplib::Client client(opa_host_, 8181);

    client.set_connection_timeout(2, 0);
    client.set_read_timeout(3, 0);

    const nlohmann::json request_body = {
        {"input", {
            {"subject", {
                {"username", request.subject.username},
                {"role", request.subject.role},
                {"auth_level", request.subject.auth_level},
                {"allowed_device_ids", request.subject.allowed_device_ids},
                {"account_expires_at", request.subject.account_expires_at}
            }},
            {"device", {
                {"id", request.device_id},
                {"key_verified", request.device_key_verified}
            }},
            {"context", {
                {"location_id", request.location_id}
            }},
            {"resource", {
                {"id", request.resource.id},
                {"sensitivity", request.resource.sensitivity},
                {"level", request.resource.level}
            }},
            {"action", request.action}
        }}
    };

    const auto response = client.Post(
        "/v1/data/zerotrust/authz/decision",
        request_body.dump(),
        "application/json"
    );

    if (!response || response->status != 200) {
        return std::nullopt;
    }

    try {
        const auto payload =
            nlohmann::json::parse(response->body);

        if (!payload.contains("result")) {
            return std::nullopt;
        }

        const auto& result = payload.at("result");

        const std::string effect =
            result.value("effect", "");

        const std::string reason_code =
            result.value("reason_code", "");

        if (effect.empty() || reason_code.empty()) {
            return std::nullopt;
        }

        return AccessDecision{
            true,
            effect,
            result.value("rule_id", "ZTAS-0000"),
            reason_code,
            result.value("severity", "info"),
            result.value("policy_version", "unknown"),
            result.value(
                "current_auth_level",
                request.subject.auth_level
            ),
            result.value(
                "required_auth_level",
                request.subject.auth_level
            ),
            request.resource.id
        };
    } catch (const nlohmann::json::parse_error&) {
        return std::nullopt;
    }
}
