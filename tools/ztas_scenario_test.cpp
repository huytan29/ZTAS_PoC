#include "ztas/authorization/access_types.hpp"
#include "ztas/policy/policy_client.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

struct Scenario {
    std::string id;
    std::string description;
    AccessRequest request;
    std::string expected_effect;
    std::string expected_reason;
};

AccessSubject subject(
    std::string username,
    std::string role,
    int auth_level,
    std::string organization_unit,
    std::vector<std::string> assigned_tasks,
    std::string device_id
) {
    return AccessSubject{
        std::move(username),
        std::move(role),
        auth_level,
        {std::move(device_id)},
        0,
        "",
        "",
        "",
        std::move(organization_unit),
        std::move(assigned_tasks)
    };
}

ProtectedResource resource(
    std::string id,
    int level,
    std::string organization_unit,
    std::string required_task
) {
    return ProtectedResource{
        std::move(id),
        "test-fixture",
        level,
        "",
        std::move(organization_unit),
        std::move(required_task)
    };
}

AccessRequest request_for(
    AccessSubject access_subject,
    std::string device_id,
    std::string location_id,
    ProtectedResource protected_resource
) {
    return AccessRequest{
        std::move(access_subject),
        std::move(device_id),
        std::move(location_id),
        true,
        "127.0.0.1",
        true,
        std::move(protected_resource),
        "read"
    };
}

std::vector<Scenario> make_scenarios() {
    const std::string trusted_device = "admin-console";
    const std::string trusted_location = "secure-zone";

    return {
        {
            "TC-01",
            "Chuyen vien A, dung don vi/nhiem vu, thiet bi Trusted, doc tai lieu Noi bo A.",
            request_for(
                subject("specialist-a", "employee", 1, "unit-a", {"internal-a"}, trusted_device),
                trusted_device,
                trusted_location,
                resource("internal_document", 2, "unit-a", "internal-a")
            ),
            "PERMIT",
            "ACCESS_GRANTED"
        },
        {
            "TC-02",
            "Chuyen vien B, thiet bi Trusted, truy cap tai lieu Noi bo A ngoai don vi duoc giao.",
            request_for(
                subject("specialist-b", "employee", 1, "unit-b", {"internal-a"}, trusted_device),
                trusted_device,
                trusted_location,
                resource("internal_document", 2, "unit-a", "internal-a")
            ),
            "DENY",
            "ORGANIZATION_UNIT_NOT_ALLOWED"
        },
        {
            "TC-03",
            "Chuyen vien A truy cap tai lieu Noi bo A tu thiet bi chua duoc Trusted/dang ky.",
            request_for(
                subject("specialist-a", "employee", 1, "unit-a", {"internal-a"}, "guest-laptop-01"),
                "guest-laptop-01",
                "external-network",
                resource("internal_document", 2, "unit-a", "internal-a")
            ),
            "DENY",
            "DEVICE_REGISTRATION_INACTIVE"
        },
        {
            "TC-04",
            "Quan ly A, thiet bi Trusted, da Step-Up, truy cap tai lieu Mat/nhay cam A.",
            request_for(
                subject("manager-a", "manager", 2, "unit-a", {"sensitive-a"}, trusted_device),
                trusted_device,
                trusted_location,
                resource("confidential_document", 3, "unit-a", "sensitive-a")
            ),
            "PERMIT",
            "ACCESS_GRANTED"
        },
        {
            "TC-05",
            "Quan tri he thong, thiet bi Trusted, truy cap noi dung Han che dac biet mo phong.",
            request_for(
                subject("system-admin", "admin", 5, "unit-a", {"*"}, trusted_device),
                trusted_device,
                trusted_location,
                resource("restricted_document", 5, "unit-a", "restricted-a")
            ),
            "DENY",
            "ROLE_LEVEL_INSUFFICIENT"
        }
    };
}

} // namespace

int main(int argc, char* argv[]) {
    const std::string opa_host = argc >= 2 ? argv[1] : "127.0.0.1";
    const std::string report_path = argc >= 3
        ? argv[2]
        : "runtime/test-reports/scenario-report.json";

    PolicyClient policy_client(opa_host);
    const auto scenarios = make_scenarios();
    nlohmann::json results = nlohmann::json::array();
    int passed = 0;

    std::cout << "ZTAS - KIEM THU 5 KICH BAN DE CUONG\n";
    std::cout << "OPA: " << opa_host << ":8181\n\n";

    for (const auto& scenario : scenarios) {
        const auto decision = policy_client.decide(scenario.request);
        const bool is_pass = decision.has_value() &&
            decision->effect == scenario.expected_effect &&
            decision->reason_code == scenario.expected_reason;
        passed += is_pass ? 1 : 0;

        std::cout << (is_pass ? "[PASS] " : "[FAIL] ")
                  << scenario.id << " - " << scenario.description << "\n";
        std::cout << "       Expected: " << scenario.expected_effect
                  << " / " << scenario.expected_reason << "\n";
        if (decision) {
            std::cout << "       Actual:   " << decision->effect
                      << " / " << decision->reason_code
                      << " (" << decision->rule_id << ")\n";
        } else {
            std::cout << "       Actual:   OPA_UNAVAILABLE_OR_INVALID_RESPONSE\n";
        }

        results.push_back({
            {"id", scenario.id},
            {"description", scenario.description},
            {"expected", {{"effect", scenario.expected_effect}, {"reason_code", scenario.expected_reason}}},
            {"actual", decision ? nlohmann::json{{"effect", decision->effect}, {"reason_code", decision->reason_code}, {"rule_id", decision->rule_id}} : nlohmann::json(nullptr)},
            {"passed", is_pass}
        });
    }

    const nlohmann::json report = {
        {"tool", "ztas_scenario_test"},
        {"opa_host", opa_host},
        {"total", scenarios.size()},
        {"passed", passed},
        {"failed", static_cast<int>(scenarios.size()) - passed},
        {"results", results}
    };

    const std::filesystem::path output(report_path);
    if (!output.parent_path().empty()) {
        std::filesystem::create_directories(output.parent_path());
    }
    std::ofstream report_file(output);
    report_file << report.dump(2) << '\n';

    std::cout << "\nKet qua: " << passed << "/" << scenarios.size()
              << " PASS. Bao cao: " << output.string() << "\n";
    return passed == static_cast<int>(scenarios.size()) ? 0 : 1;
}
