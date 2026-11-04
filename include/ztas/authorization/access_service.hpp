#pragma once

#include "ztas/authorization/access_types.hpp"

class AuditLogger;
class PolicyClient;

class AccessService {
public:
    AccessService(
        const PolicyClient& policy_client,
        const AuditLogger& audit_logger
    );

    AccessDecision authorize(
        const AccessRequest& request
    ) const;

private:
    const PolicyClient& policy_client_;
    const AuditLogger& audit_logger_;
};