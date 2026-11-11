#include "ztas/authorization/access_service.hpp"

#include "ztas/audit/audit_logger.hpp"
#include "ztas/policy/policy_client.hpp"

AccessService::AccessService(
    const PolicyClient& policy_client,
    const AuditLogger& audit_logger
) : policy_client_(policy_client),
    audit_logger_(audit_logger) {}

AccessDecision AccessService::authorize(
    const AccessRequest& request
) const {
    const auto policy_decision =
        policy_client_.decide(request);

    if (!policy_decision.has_value()) {
        audit_logger_.write({
            {"event_type", "AUTHZ_ERROR"},
            {"username", request.subject.username},
            {"role", request.subject.role},
            {"auth_level", request.subject.auth_level},
            {"account_expires_at", request.subject.account_expires_at},
            {"device_id", request.device_id},
            {"device_key_verified", request.device_key_verified},
            {"source_ip", request.source_ip},
            {"source_ip_verified", request.source_ip_verified},
            {"location_id", request.location_id},
            {"resource_id", request.resource.id},
            {"resource_level", request.resource.level},
            {"action", request.action},
            {"rule_id", "ZTAS-9001"},
            {"reason_code", "OPA_UNAVAILABLE"},
            {"severity", "critical"}
        });

        return {
            false,
            "DENY",
            "ZTAS-9001",
            "OPA_UNAVAILABLE",
            "critical",
            "unavailable",
            request.subject.auth_level,
            request.subject.auth_level,
            request.resource.id
        };
    }

    AccessDecision decision = *policy_decision;
    decision.resource_id = request.resource.id;

    audit_logger_.write({
        {"event_type", "AUTHZ_DECISION"},
        {"username", request.subject.username},
        {"role", request.subject.role},
        {"auth_level", request.subject.auth_level},
        {"account_expires_at", request.subject.account_expires_at},
        {"device_id", request.device_id},
        {"device_key_verified", request.device_key_verified},
        {"source_ip", request.source_ip},
        {"source_ip_verified", request.source_ip_verified},
        {"location_id", request.location_id},
        {"resource_id", request.resource.id},
        {"resource_level", request.resource.level},
        {"action", request.action},
        {"effect", decision.effect},
        {"rule_id", decision.rule_id},
        {"reason_code", decision.reason_code},
        {"severity", decision.severity},
        {"current_auth_level", decision.current_auth_level},
        {"required_auth_level", decision.required_auth_level},
        {"policy_version", decision.policy_version}
    });

    return decision;
}
